package com.ejdev.securitylab.common.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.Value;

import java.time.Instant;
import java.util.Map;

@Value
@Builder
@Getter
@Setter
public class ApiErrorResponse {
    Instant timestamp;
    int status;
    String error;
    String code;
    String message;
    String path;
    Map<String, String> validationErrors;
}