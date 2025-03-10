package com.eunx.kyc.exception;

import org.springframework.http.HttpStatusCode;

public class CustomException extends RuntimeException {
    private final HttpStatusCode status;

    public CustomException(String message, HttpStatusCode status) {
        super(message);
        this.status = status;
    }

    public HttpStatusCode getStatus() {
        return status;
    }
}