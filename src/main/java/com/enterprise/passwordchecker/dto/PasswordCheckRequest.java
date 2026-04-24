package com.enterprise.passwordchecker.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request payload for single password strength evaluation.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(name = "PasswordCheckRequest", description = "Payload for evaluating a single password")
public class PasswordCheckRequest {

    @Schema(
            description = "The password to evaluate. Never logged or stored.",
            example = "MyS3cur3P@ssw0rd!",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    @NotBlank(message = "Password must not be blank")
    @Size(min = 1, max = 512, message = "Password length must be between 1 and 512 characters")
    private String password;

    @Schema(
            description = "Optional username — used to detect password/username similarity.",
            example = "john.doe"
    )
    @Size(max = 100, message = "Username must not exceed 100 characters")
    private String username;

    @Schema(
            description = "Policy preset to apply. Defaults to ENTERPRISE_DEFAULT.",
            example = "ENTERPRISE_DEFAULT",
            allowableValues = {"ENTERPRISE_DEFAULT", "LEGACY", "PRIVILEGED"}
    )
    @Pattern(regexp = "ENTERPRISE_DEFAULT|LEGACY|PRIVILEGED",
             message = "policyId must be ENTERPRISE_DEFAULT, LEGACY, or PRIVILEGED")
    private String policyId;

    @Schema(description = "Include detailed character composition breakdown in response.")
    @Builder.Default
    private boolean includeComposition = true;

    @Schema(description = "Include estimated crack-time analysis in response.")
    @Builder.Default
    private boolean includeCrackTime = true;
}
