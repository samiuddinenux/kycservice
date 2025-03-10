package com.eunx.kyc.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;
import java.time.LocalDateTime;

@Table("kyc_record")
public class KycRecord {

    @Id
    private String externalUserId;
    private String applicantId;
    private String reviewStatus;
    private String reviewAnswer;
    private String rejectLabels;
    private boolean verified;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Getters and Setters

    public String getExternalUserId() {
        return externalUserId;
    }

    public void setExternalUserId(String externalUserId) {
        this.externalUserId = externalUserId;
    }

    public String getApplicantId() {
        return applicantId;
    }

    public void setApplicantId(String applicantId) {
        this.applicantId = applicantId;
    }

    public String getReviewStatus() {
        return reviewStatus;
    }

    public void setReviewStatus(String reviewStatus) {
        this.reviewStatus = reviewStatus;
    }

    public String getReviewAnswer() {
        return reviewAnswer;
    }

    public void setReviewAnswer(String reviewAnswer) {
        this.reviewAnswer = reviewAnswer;
    }

    public String getRejectLabels() {
        return rejectLabels;
    }

    public void setRejectLabels(String rejectLabels) {
        this.rejectLabels = rejectLabels;
    }

    public boolean isVerified() {
        return verified;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
