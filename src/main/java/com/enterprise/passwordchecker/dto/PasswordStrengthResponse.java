package com.enterprise.passwordchecker.dto;

import com.enterprise.passwordchecker.model.PasswordStrength;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(name = "PasswordStrengthResponse", description = "Complete password strength evaluation result")
public class PasswordStrengthResponse {

    @Schema(description = "Composite strength score from 0 (worst) to 100 (best)", example = "74")
    private int score;

    @Schema(description = "Strength classification based on composite score")
    private PasswordStrength strength;

    @Schema(description = "Whether the password satisfies the applied policy")
    private boolean policyCompliant;

    @Schema(description = "Applied policy identifier", example = "ENTERPRISE_DEFAULT")
    private String appliedPolicyId;

    @Schema(description = "Specific policy violations, if any")
    private List<String> policyViolations;

    @Schema(description = "Actionable suggestions to improve the password")
    private List<String> suggestions;

    @Schema(description = "Character composition analysis")
    private CharacterComposition composition;

    @Schema(description = "Estimated crack times across attack scenarios")
    private CrackTimeEstimate crackTime;

    @Schema(description = "Entropy score in bits", example = "62.4")
    private double entropyBits;

    @Schema(description = "Detected patterns that reduce effective entropy")
    private List<String> detectedPatterns;

    @Schema(description = "ISO 8601 evaluation timestamp")
    private Instant evaluatedAt;

    @Schema(description = "API version that produced this response", example = "1.0.0")
    private String apiVersion;
}
