package com.eunx.kyc.service;

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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Map;

@Service
public class KycService {

    private static final Logger logger = LoggerFactory.getLogger(KycService.class);

    @Autowired private KycRepository kycRepository;
    @Autowired private R2dbcEntityTemplate r2dbcEntityTemplate;
    @Autowired private WebClient webClient;

    @Value("${sumsub.api.url}") private String sumsubApiUrl;
    @Value("${sumsub.api.token}") private String sumsubApiToken;
    @Value("${sumsub.api.secret}") private String sumsubApiSecret;
    @Value("${sumsub.verification.level}") private String sumsubVerificationLevel;
    @Value("${auth.service.url}") private String authServiceUrl;

    public Mono<String> initiateKyc(String token) {
        logger.debug("Initiating KYC with token: {}", token);
        if (token == null || token.trim().isEmpty() || !token.startsWith("Bearer ")) {
            logger.error("Invalid or missing token for KYC initiation: {}", token);
            return Mono.error(new CustomException("Valid Bearer token is required", HttpStatus.UNAUTHORIZED));
        }
        return verifyUserFromToken(token)
                .flatMap(userData -> {
                    String externalId = (String) userData.get("externalId");
                    String email = (String) userData.get("email");
                    if (externalId == null || externalId.isEmpty()) {
                        logger.warn("No externalId found for token. Cannot proceed with KYC.");
                        return Mono.error(new CustomException("User externalId not found", HttpStatus.BAD_REQUEST));
                    }
                    logger.debug("Using externalId: {}", externalId);
                    return kycRepository.findByExternalUserId(externalId)
                            .switchIfEmpty(Mono.just(new KycRecord()))
                            .flatMap(existingRecord -> {
                                if (existingRecord.getExternalUserId() != null && existingRecord.isVerified()) {
                                    logger.warn("KYC already verified for externalId: {}", externalId);
                                    return Mono.error(new CustomException("KYC already verified", HttpStatus.BAD_REQUEST));
                                }
                                return generateSumsubAccessToken(externalId)
                                        .doOnNext(accessToken -> logger.debug("Generated Sumsub token: {}", accessToken))
                                        .flatMap(accessToken -> saveInitialKycRecord(externalId, accessToken));
                            });
                })
                .doOnError(e -> logger.error("KYC initiation failed: {}", e.getMessage()));
    }

    public Mono<String> getKycStatusFromSumsub(String externalUserId) {
        String encodedUserId = URLEncoder.encode(externalUserId, StandardCharsets.UTF_8);
        String url = sumsubApiUrl + "/resources/applicants/-;externalUserId=" + encodedUserId + "/one";
        String timestamp = String.valueOf(System.currentTimeMillis() / 1000L);
        String method = "GET";
        String path = "/resources/applicants/-;externalUserId=" + encodedUserId + "/one";
        String body = "";
        String signature = generateSumsubSignature(timestamp, method, path, body);

        return webClient.get()
                .uri(url)
                .header("X-App-Token", sumsubApiToken)
                .header("X-App-Access-Ts", timestamp)
                .header("X-App-Access-Sig", signature)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .map(result -> {
                    Map<String, Object> review = (Map<String, Object>) result.get("review");
                    return review != null ? (String) review.get("reviewStatus") : "pending";
                })
                .onErrorResume(e -> Mono.error(new CustomException("Failed to fetch KYC status", HttpStatus.INTERNAL_SERVER_ERROR)));
    }

    public Mono<String> getKycStatusFromSumsubByEmail(String email) {
        return verifyUser(email, null)
                .flatMap(userData -> {
                    String externalId = (String) userData.get("externalId");
                    return getKycStatusFromSumsub(externalId);
                });
    }

    public Mono<Void> updateKycStatusInDb(String email, String kycStatus) {
        return verifyUser(email, null)
                .flatMap(userData -> {
                    String externalId = (String) userData.get("externalId");
                    return kycRepository.findByExternalUserId(externalId)
                            .flatMap(kycRecord -> {
                                kycRecord.setReviewStatus(kycStatus);
                                kycRecord.setVerified("completed".equalsIgnoreCase(kycStatus));
                                kycRecord.setUpdatedAt(LocalDateTime.now());
                                return kycRepository.save(kycRecord);
                            })
                            .switchIfEmpty(Mono.defer(() -> {
                                KycRecord newRecord = new KycRecord();
                                newRecord.setExternalUserId(externalId);
                                newRecord.setReviewStatus(kycStatus);
                                newRecord.setVerified("completed".equalsIgnoreCase(kycStatus));
                                newRecord.setCreatedAt(LocalDateTime.now());
                                newRecord.setUpdatedAt(LocalDateTime.now());
                                return r2dbcEntityTemplate.insert(newRecord);
                            }))
                            .then();
                });
    }

    @Retry(name = "sumsub")
    private Mono<String> generateSumsubAccessToken(String externalUserId) {
        String encodedUserId = URLEncoder.encode(externalUserId, StandardCharsets.UTF_8);
        String encodedLevel = URLEncoder.encode(sumsubVerificationLevel, StandardCharsets.UTF_8);
        String path = "/resources/accessTokens?userId=" + encodedUserId + "&levelName=" + encodedLevel + "&ttlInSecs=3600";
        String url = sumsubApiUrl + path;
        String timestamp = String.valueOf(System.currentTimeMillis() / 1000L);
        String method = "POST";
        String body = "";
        String signature = generateSumsubSignature(timestamp, method, path, body);

        return webClient.post()
                .uri(url)
                .header("X-App-Token", sumsubApiToken)
                .header("X-App-Access-Ts", timestamp)
                .header("X-App-Access-Sig", signature)
                .contentType(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .map(result -> (String) result.get("token"))
                .doOnError(e -> logger.error("Sumsub token generation failed: {}", e.getMessage()));
    }

    private Mono<Map<String, Object>> verifyUserFromToken(String token) {
        logger.debug("Verifying user with token: {}", token);
        return webClient.get()
                .uri(authServiceUrl + "/user")
                .header("Authorization", token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .flatMap(response -> {
                    Map<String, Object> userData = (Map<String, Object>) response.get("data");
                    if (userData == null) {
                        logger.error("No 'data' field in auth response for token");
                        return Mono.error(new CustomException("Invalid auth response", HttpStatus.INTERNAL_SERVER_ERROR));
                    }
                    return Mono.just(userData);
                })
                .doOnNext(data -> logger.debug("Verified user data: {}", data))
                .doOnError(e -> logger.error("Failed to verify user: {}", e.getMessage()));
    }

    private Mono<Map<String, Object>> verifyUser(String email, String token) {
        // This method remains for backward compatibility or other uses
        return verifyUserFromToken(token != null ? token : "Bearer dummy")
                .flatMap(userData -> {
                    if (!email.equals(userData.get("email"))) {
                        logger.warn("Email mismatch: request={} vs response={}", email, userData.get("email"));
                        return Mono.error(new CustomException("User not found or email mismatch", HttpStatus.NOT_FOUND));
                    }
                    return Mono.just(userData);
                });
    }

    public Mono<String> saveInitialKycRecord(String externalUserId, String accessToken) {
        return kycRepository.findByExternalUserId(externalUserId)
                .flatMap(existingRecord -> {
                    existingRecord.setReviewStatus("init");
                    existingRecord.setUpdatedAt(LocalDateTime.now());
                    return kycRepository.save(existingRecord).thenReturn(accessToken);
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

    public Mono<KycRecord> getKycRecordFromDbByEmail(String email) {
        return verifyUser(email, null)
                .flatMap(userData -> {
                    String externalId = (String) userData.get("externalId");
                    return kycRepository.findByExternalUserId(externalId);
                })
                .switchIfEmpty(Mono.error(new CustomException("No KYC record found for email " + email, HttpStatus.NOT_FOUND)));
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
                    kycRepository.save(kycRecord).subscribe();
                }).subscribe();
    }

    private String generateSumsubSignature(String timestamp, String method, String path, String body) {
        try {
            String data = timestamp + method + path + body;
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(sumsubApiSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Signature generation failed", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}