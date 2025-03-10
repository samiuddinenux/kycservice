package com.eunx.kyc.dto;

import lombok.Data;

@Data
public class KycResponse {
    private String applicantId;
    private String status;
    private String message;

    public String getApplicantId() {
        return applicantId;
    }

    public void setApplicantId(String applicantId) {
        this.applicantId = applicantId;
    }
}