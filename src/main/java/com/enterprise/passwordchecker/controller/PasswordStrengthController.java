package com.enterprise.passwordchecker.controller;

import com.enterprise.passwordchecker.dto.*;
import com.enterprise.passwordchecker.model.PasswordPolicy;
import com.enterprise.passwordchecker.service.PasswordPolicyService;
import com.enterprise.passwordchecker.service.PasswordStrengthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;

/**
 * REST controller exposing password strength evaluation and policy management endpoints.
 *
 * <p>All endpoints are versioned under {@code /api/v1}.
 * Passwords are evaluated in-memory and never persisted.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/password")
@RequiredArgsConstructor
@Tag(name = "Password Evaluation", description = "Core password strength analysis and scoring")
public class PasswordStrengthController {

    private final PasswordStrengthService passwordStrengthService;
    private final PasswordPolicyService passwordPolicyService;

    // ─────────────────────────────────────────────────────────────────────────
    // Single Evaluation
    // ─────────────────────────────────────────────────────────────────────────

    @Operation(
            summary = "Evaluate password strength",
            description = """
                    Evaluates a single password against a configurable policy and returns a 
                    comprehensive strength report including:
                    - Composite score (0–100)
                    - Strength classification (VERY_WEAK → VERY_STRONG)
                    - Policy compliance verdict
                    - Actionable improvement suggestions
                    - Character composition breakdown
                    - Estimated crack times (zxcvbn-powered)
                    
                    **Security**: Passwords are evaluated in-memory and never logged or persisted.
                    """,
            tags = {"Password Evaluation"}
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Password evaluated successfully",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = PasswordStrengthResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request payload",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ErrorResponse.class),
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "status": 400,
                                              "error": "VALIDATION_ERROR",
                                              "message": "Password must not be blank",
                                              "path": "/api/v1/password/check",
                                              "fieldErrors": { "password": "must not be blank" }
                                            }
                                            """
                            )
                    )
            ),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping(
            value = "/check",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<PasswordStrengthResponse> checkPassword(
            @Valid @RequestBody
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Password evaluation request",
                    required = true,
                    content = @Content(
                            examples = @ExampleObject(
                                    name = "Standard evaluation",
                                    value = """
                                            {
                                              "password": "MyS3cur3P@ssw0rd!",
                                              "username": "john.doe",
                                              "policyId": "ENTERPRISE_DEFAULT",
                                              "includeComposition": true,
                                              "includeCrackTime": true
                                            }
                                            """
                            )
                    )
            )
            PasswordCheckRequest request
    ) {
        log.info("POST /api/v1/password/check policyId={}", request.getPolicyId());
        PasswordStrengthResponse response = passwordStrengthService.evaluate(request);
        return ResponseEntity.ok(response);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bulk Evaluation
    // ─────────────────────────────────────────────────────────────────────────

    @Operation(
            summary = "Bulk password evaluation",
            description = """
                    Evaluates up to 50 passwords in a single request. Returns individual 
                    results alongside aggregated metrics including average score, 
                    policy compliance rate, and strength distribution.
                    
                    Useful for audit workflows, new-user onboarding validation, and 
                    security posture assessments.
                    """,
            tags = {"Bulk Operations"}
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Batch evaluated successfully",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = BulkPasswordStrengthResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Validation error (e.g. batch size > 50)",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))
            )
    })
    @PostMapping(
            value = "/check/bulk",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Tag(name = "Bulk Operations")
    public ResponseEntity<BulkPasswordStrengthResponse> checkBulk(
            @Valid @RequestBody BulkPasswordCheckRequest request
    ) {
        log.info("POST /api/v1/password/check/bulk count={}, policyId={}",
                request.getPasswords().size(), request.getPolicyId());
        BulkPasswordStrengthResponse response = passwordStrengthService.evaluateBulk(request);
        return ResponseEntity.ok(response);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Policy Management
    // ─────────────────────────────────────────────────────────────────────────

    @Operation(
            summary = "List available password policies",
            description = "Returns all registered password policy presets with their rule configurations.",
            tags = {"Policy Management"}
    )
    @ApiResponse(
            responseCode = "200",
            description = "Policy list retrieved successfully"
    )
    @GetMapping(value = "/policies", produces = MediaType.APPLICATION_JSON_VALUE)
    @Tag(name = "Policy Management")
    public ResponseEntity<Collection<PasswordPolicy>> listPolicies() {
        log.debug("GET /api/v1/password/policies");
        return ResponseEntity.ok(passwordPolicyService.listPolicies());
    }

    @Operation(
            summary = "Get a specific password policy",
            description = "Retrieves a single policy by its identifier.",
            tags = {"Policy Management"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Policy found"),
            @ApiResponse(responseCode = "404", description = "Policy not found",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @GetMapping(value = "/policies/{policyId}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Tag(name = "Policy Management")
    public ResponseEntity<PasswordPolicy> getPolicy(
            @Parameter(description = "Policy identifier", example = "ENTERPRISE_DEFAULT",
                       schema = @Schema(allowableValues = {"ENTERPRISE_DEFAULT", "LEGACY", "PRIVILEGED"}))
            @PathVariable String policyId
    ) {
        log.debug("GET /api/v1/password/policies/{}", policyId);
        PasswordPolicy policy = passwordPolicyService.resolve(policyId);
        return ResponseEntity.ok(policy);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Health Check (supplemental — Actuator is the canonical health endpoint)
    // ─────────────────────────────────────────────────────────────────────────

    @Operation(
            summary = "API health check",
            description = "Lightweight liveness probe for load balancers and monitoring systems.",
            tags = {"Health & Metrics"}
    )
    @ApiResponse(responseCode = "200", description = "Service is healthy")
    @GetMapping(value = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    @Tag(name = "Health & Metrics")
    public ResponseEntity<HealthResponse> health() {
        return ResponseEntity.ok(new HealthResponse("UP", "Password Strength Checker API is running"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Inner record for health endpoint
    // ─────────────────────────────────────────────────────────────────────────

    @Schema(description = "API health status")
    public record HealthResponse(
            @Schema(description = "Status code", example = "UP") String status,
            @Schema(description = "Descriptive message") String message
    ) {}
}
