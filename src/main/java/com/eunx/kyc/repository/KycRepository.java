package com.eunx.kyc.repository;

import com.eunx.kyc.entity.KycRecord;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import reactor.core.publisher.Mono;

public interface KycRepository extends R2dbcRepository<KycRecord, String> {
    Mono<KycRecord> findByExternalUserId(String externalUserId);
    Mono<KycRecord> findByApplicantId(String applicantId);
}