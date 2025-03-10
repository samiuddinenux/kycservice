package com.eunx.kyc.service;

import com.eunx.kyc.dto.KycRequest;
import com.eunx.kyc.entity.KycRecord;
import com.eunx.kyc.exception.CustomException;
import com.eunx.kyc.repository.KycRepository;
import io.github.resilience4j.retry.annotation.Retry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Map;

@Service
public class KycService {

    private static final Logger logger = LoggerFactory.getLogger(KycService.class);

    @Autowired
    private KycRepository kycRepository;

    @Autowired
    private R2dbcEntityTemplate r2dbcEntityTemplate;

    @Autowired
    private WebClient webClient;

    @Value("${sumsub.api.url}")
    private String sumsubApiUrl;

    @Value("${sumsub.api.token}")
    private String sumsubApiToken;

    @Value("${sumsub.api.secret}")
    private String sumsubApiSecret;

    @Value("${sumsub.verification.level}")
    private String sumsubVerificationLevel;

    @Value("${auth.service.url}")
    private String authServiceUrl;

    public Mono<String> initiateKyc(KycRequest request, String token) {
        logger.debug("Entering initiateKyc for username: {}", request.getUsername());
        logger.info("Initiating KYC for externalUserId: {}", request.getUsername());
        return verifyUser(request.getUsername(), token)
                .flatMap(userData -> {
                    logger.debug("User verified: {}", userData);
                    return kycRepository.findByExternalUserId(request.getUsername())
                            .switchIfEmpty(Mono.just(new KycRecord()))
                            .flatMap(existingRecord -> {
                                if (existingRecord.getExternalUserId() != null && existingRecord.isVerified()) {
                                    logger.warn("KYC already verified for: {}", request.getUsername());
                                    return Mono.error(new CustomException("KYC already verified", HttpStatus.BAD_REQUEST));
                                }
                                return generateSumsubAccessToken(request.getUsername())
                                        .flatMap(accessToken -> {
                                            logger.info("Generated Sumsub access token for {}: {}", request.getUsername(), accessToken);
                                            return saveInitialKycRecord(request.getUsername(), accessToken);
                                        });
                            });
                })
                .doOnError(e -> logger.error("Initiate KYC failed: {}", e.getMessage(), e));
    }

    public Mono<String> getKycStatusFromSumsub(String externalUserId) {
        try {
            String encodedUserId = java.net.URLEncoder.encode(externalUserId, StandardCharsets.UTF_8.name());
            String url = sumsubApiUrl + "/resources/applicants/-;externalUserId=" + encodedUserId + "/one";
            logger.debug("Fetching KYC status from Sumsub URL: {}", url);
            String timestamp = String.valueOf(System.currentTimeMillis() / 1000L);
            String method = "GET";
            String path = "/resources/applicants/-;externalUserId=" + encodedUserId + "/one";
            String body = "";
            String signature = generateSumsubSignature(timestamp, method, path, body);
            logger.debug("Sumsub request headers - X-App-Token: {}, X-App-Access-Ts: {}, X-App-Access-Sig: {}",
                    sumsubApiToken, timestamp, signature);

            return webClient.get()
                    .uri(url)
                    .header("X-App-Token", sumsubApiToken)
                    .header("X-App-Access-Ts", timestamp)
                    .header("X-App-Access-Sig", signature)
                    .retrieve()
                    .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                            response -> response.bodyToMono(String.class)
                                    .doOnNext(bodyStr -> logger.error("Sumsub API error response: {}", bodyStr))
                                    .map(bodyStr -> new CustomException("Sumsub error: " + bodyStr, response.statusCode())))
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .map(result -> {
                        Map<String, Object> review = (Map<String, Object>) result.get("review");
                        String status = review != null ? (String) review.get("reviewStatus") : "pending";
                        logger.debug("Sumsub status for {}: {}", externalUserId, status);
                        return status != null ? status : "pending";
                    })
                    .doOnError(e -> logger.error("Failed to fetch KYC status from Sumsub: {}", e.getMessage()));
        } catch (Exception e) {
            logger.error("Error in getKycStatusFromSumsub: {}", e.getMessage());
            return Mono.error(new CustomException("Failed to fetch KYC status", HttpStatus.INTERNAL_SERVER_ERROR));
        }
    }

    public Mono<Void> updateKycStatusInDb(String externalUserId, String kycStatus) {
        return kycRepository.findByExternalUserId(externalUserId)
                .flatMap(kycRecord -> {
                    kycRecord.setReviewStatus(kycStatus);
                    kycRecord.setVerified("completed".equalsIgnoreCase(kycStatus));
                    kycRecord.setUpdatedAt(LocalDateTime.now());
                    return kycRepository.save(kycRecord)
                            .doOnSuccess(saved -> logger.info("Updated KYC status in DB for: {}", externalUserId));
                })
                .switchIfEmpty(Mono.defer(() -> {
                    KycRecord newRecord = new KycRecord();
                    newRecord.setExternalUserId(externalUserId);
                    newRecord.setReviewStatus(kycStatus);
                    newRecord.setVerified("completed".equalsIgnoreCase(kycStatus));
                    newRecord.setCreatedAt(LocalDateTime.now());
                    newRecord.setUpdatedAt(LocalDateTime.now());
                    return r2dbcEntityTemplate.insert(newRecord)
                            .doOnSuccess(saved -> logger.info("Inserted new KYC record in DB for: {}", externalUserId));
                }))
                .then();
    }

    @Retry(name = "sumsub")
    private Mono<String> generateSumsubAccessToken(String externalUserId) {
        try {
            String encodedUserId = java.net.URLEncoder.encode(externalUserId, StandardCharsets.UTF_8.name());
            String encodedLevel = java.net.URLEncoder.encode(sumsubVerificationLevel, StandardCharsets.UTF_8.name());
            String path = "/resources/accessTokens?userId=" + encodedUserId + "&levelName=" + encodedLevel + "&ttlInSecs=3600";
            String url = sumsubApiUrl + path;
            String timestamp = String.valueOf(System.currentTimeMillis() / 1000L);
            String method = "POST";
            String body = "";
            String signature = generateSumsubSignature(timestamp, method, path, body);
            logger.debug("Generating Sumsub access token - URL: {}", url);

            return webClient.post()
                    .uri(url)
                    .header("X-App-Token", sumsubApiToken)
                    .header("X-App-Access-Ts", timestamp)
                    .header("X-App-Access-Sig", signature)
                    .contentType(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                            response -> response.bodyToMono(String.class)
                                    .map(bodyStr -> new CustomException("Sumsub error: " + bodyStr, response.statusCode())))
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .map(result -> (String) result.get("token"))
                    .doOnError(e -> logger.error("Failed to generate Sumsub access token: {}", e.getMessage(), e));
        } catch (Exception e) {
            return Mono.error(e);
        }
    }

    private Mono<Map<String, Object>> verifyUser(String username, String token) {
        logger.debug("Verifying user {} with auth-service", username);
        return webClient.get()
                .uri(authServiceUrl + "/user/" + username)
                .header("Authorization", token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .doOnError(e -> logger.error("Failed to verify user: {}", e.getMessage()))
                .switchIfEmpty(Mono.error(new CustomException("User not found", HttpStatus.NOT_FOUND)));
    }

    public Mono<String> saveInitialKycRecord(String externalUserId, String accessToken) {
        return kycRepository.findByExternalUserId(externalUserId)
                .flatMap(existingRecord -> {
                    existingRecord.setReviewStatus("init");
                    existingRecord.setUpdatedAt(LocalDateTime.now());
                    return kycRepository.save(existingRecord)
                            .thenReturn(accessToken);
                })
                .switchIfEmpty(Mono.defer(() -> {
                    KycRecord newRecord = new KycRecord();
                    newRecord.setExternalUserId(externalUserId);
                    newRecord.setReviewStatus("init");
                    newRecord.setCreatedAt(LocalDateTime.now());
                    newRecord.setUpdatedAt(LocalDateTime.now());
                    return r2dbcEntityTemplate.insert(newRecord).thenReturn(accessToken);
                }));
    }

    public Mono<KycRecord> getKycRecordFromDb(String externalUserId) {
        return kycRepository.findByExternalUserId(externalUserId)
                .switchIfEmpty(Mono.error(new CustomException("No KYC record found for " + externalUserId, HttpStatus.NOT_FOUND)));
    }

    public void updateKycStatus(Map<String, Object> webhookData) {
        String applicantId = (String) webhookData.get("applicantId");
        String externalUserId = (String) webhookData.get("externalUserId");
        String reviewStatus = (String) webhookData.get("reviewStatus");
        Map<String, Object> reviewResult = (Map<String, Object>) webhookData.get("reviewResult");

        if (applicantId == null || reviewStatus == null) {
            logger.error("Invalid webhook data: {}", webhookData);
            return;
        }

        String lookupId = externalUserId != null ? externalUserId : applicantId;

        kycRepository.findByExternalUserId(lookupId)
                .switchIfEmpty(kycRepository.findByApplicantId(applicantId))
                .defaultIfEmpty(new KycRecord())
                .doOnNext(kycRecord -> {
                    if (kycRecord.getExternalUserId() == null) {
                        kycRecord.setExternalUserId(lookupId);
                    }
                    kycRecord.setApplicantId(applicantId);
                    kycRecord.setReviewStatus(reviewStatus);
                    kycRecord.setVerified("completed".equalsIgnoreCase(reviewStatus) &&
                            reviewResult != null && "GREEN".equalsIgnoreCase((String) reviewResult.get("reviewAnswer")));
                    if (reviewResult != null) {
                        kycRecord.setReviewAnswer((String) reviewResult.get("reviewAnswer"));
                        kycRecord.setRejectLabels((String) reviewResult.get("rejectLabels"));
                    }
                    kycRecord.setUpdatedAt(LocalDateTime.now());
                    kycRepository.save(kycRecord)
                            .doOnSuccess(saved -> logger.info("Webhook updated KYC status in DB for: {}", lookupId))
                            .subscribe();
                    logger.info("Webhook processed - applicantId: {}, reviewStatus: {}", applicantId, reviewStatus);
                }).subscribe();
    }

    private String generateSumsubSignature(String timestamp, String method, String path, String body) {
        try {
            String data = timestamp + method + path + body;
            logger.debug("Signature data: {}", data);
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(sumsubApiSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            logger.error("Failed to generate Sumsub signature: {}", e.getMessage());
            throw new RuntimeException("Signature generation failed", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}