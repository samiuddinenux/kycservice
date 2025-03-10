package com.eunx.kyc.controller;

import com.eunx.kyc.dto.KycRequest;
import com.eunx.kyc.service.KycService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

@RestController
@RequestMapping("/api/kyc")
public class KycController {

    private static final Logger logger = LoggerFactory.getLogger(KycController.class);

    @Autowired
    private KycService kycService;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${sumsub.api.secret}")
    private String sumsubApiSecret;

    @PostMapping("/initiate")
    public Mono<ResponseEntity<String>> initiateKyc(@RequestHeader("Authorization") String token,
                                                    @RequestBody KycRequest request) {
        logger.debug("Starting initiateKyc for username: {}", request.getUsername());
        return ReactiveSecurityContextHolder.getContext()
                .map(context -> context.getAuthentication().getName())
                .flatMap(authenticatedUsername -> {
                    if (!authenticatedUsername.equals(request.getUsername())) {
                        logger.warn("Token mismatch: {} vs {}", authenticatedUsername, request.getUsername());
                        return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token mismatch"));
                    }
                    logger.info("Received KYC initiation request for username: {}", request.getUsername());
                    return kycService.initiateKyc(request, token)
                            .map(ResponseEntity::ok)
                            .onErrorResume(e -> Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                    .body("KYC initiation failed: " + e.getMessage())));
                });
    }

    @PostMapping("/webhook")
    public ResponseEntity<String> handleWebhook(@RequestBody byte[] rawBody,
                                                @RequestHeader("x-payload-digest") String receivedDigest,
                                                @RequestHeader("x-payload-digest-alg") String digestAlg) {
        logger.info("Received webhook with digest: {}", receivedDigest);
        logger.debug("Raw payload: {}", new String(rawBody, StandardCharsets.UTF_8));

        String calculatedDigest = calculateHmac(rawBody, sumsubApiSecret, digestAlg);
        logger.debug("Calculated digest: {}", calculatedDigest);
        if (!receivedDigest.equals(calculatedDigest)) {
            logger.warn("Invalid webhook signature: received={}, calculated={}", receivedDigest, calculatedDigest);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid signature");
        }

        try {
            Map<String, Object> webhookData = objectMapper.readValue(rawBody, new TypeReference<>() {});
            logger.info("Webhook payload: {}", webhookData);
            kycService.updateKycStatus(webhookData);
            return ResponseEntity.ok("Webhook processed");
        } catch (Exception e) {
            logger.error("Failed to parse webhook payload: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid payload");
        }
    }

    @GetMapping("/status")
    public Mono<ResponseEntity<String>> getKycStatus(@RequestHeader("Authorization") String token) {
        return ReactiveSecurityContextHolder.getContext()
                .map(context -> context.getAuthentication().getName())
                .flatMap(externalUserId -> {
                    if (externalUserId == null || externalUserId.isEmpty()) {
                        return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .body("{\"error\": \"Invalid or expired token\"}"));
                    }
                    logger.info("Fetching KYC status for: {}", externalUserId);
                    return kycService.getKycStatusFromSumsub(externalUserId)
                            .flatMap(status -> kycService.updateKycStatusInDb(externalUserId, status)
                                    .then(Mono.just(ResponseEntity.ok(
                                            "{\"status\": \"" + status + "\", \"verified\": " + "completed".equalsIgnoreCase(status) + "}"
                                    ))))
                            .onErrorResume(e -> {
                                logger.warn("Sumsub fetch failed, falling back to DB: {}", e.getMessage());
                                return kycService.getKycRecordFromDb(externalUserId)
                                        .map(record -> ResponseEntity.ok(
                                                "{\"status\": \"" + record.getReviewStatus() + "\", \"verified\": " + record.isVerified() + "}"
                                        ))
                                        .onErrorResume(dbError -> {
                                            logger.error("No KYC record in DB: {}", dbError.getMessage());
                                            return Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND)
                                                    .body("{\"error\": \"No KYC record found for " + externalUserId + "\"}"));
                                        });
                            });
                });
    }

    private String calculateHmac(byte[] payload, String secretKey, String algorithm) {
        try {
            String hmacAlgo = algorithm.equals("HMAC_SHA256_HEX") ? "HmacSHA256" :
                    algorithm.equals("HMAC_SHA512_HEX") ? "HmacSHA512" : "HmacSHA256";
            logger.debug("Using HMAC algorithm: {}", hmacAlgo);
            Mac mac = Mac.getInstance(hmacAlgo);
            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), hmacAlgo);
            mac.init(keySpec);
            byte[] hmacBytes = mac.doFinal(payload);
            return bytesToHex(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            logger.error("Failed to calculate HMAC: {}", e.getMessage());
            throw new RuntimeException("HMAC calculation failed", e);
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