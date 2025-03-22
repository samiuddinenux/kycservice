package com.eunx.kyc.dto;

import lombok.Data;

@Data
public class KycRequest {
    private String email; // Maps to externalUserId (previously username)
}