package com.eunx.kyc.dto;

import lombok.Data;

@Data
public class KycRequest {
    private String username; // Maps to externalUserId
}