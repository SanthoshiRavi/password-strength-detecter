package com.enterprise.passwordchecker.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(name = "ErrorResponse", description = "Standard error response envelope")
public class ErrorResponse {

    @Schema(description = "HTTP status code", example = "400")
    private int status;

    @Schema(description = "Short error classification", example = "VALIDATION_ERROR")
    private String error;

    @Schema(description = "Human-readable error message", example = "Password must not be blank")
    private String message;

    @Schema(description = "Request path that triggered the error", example = "/api/v1/password/check")
    private String path;

    @Schema(description = "ISO 8601 timestamp of the error")
    private Instant timestamp;

    @Schema(description = "Field-level validation errors (if applicable)")
    private Map<String, String> fieldErrors;

    @Schema(description = "Correlation ID for distributed tracing", example = "f47ac10b-58cc")
    private String correlationId;
}
