package com.enterprise.passwordchecker.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

/**
 * Configurable password policy ruleset.
 *
 * <p>Encapsulates all constraints used during password validation.
 * Defaults follow NIST SP 800-63B and OWASP ASVS Level 2 guidelines.
 */
@Data
@Builder
@Schema(description = "Password policy configuration with all validation rules")
public class PasswordPolicy {

    @Schema(description = "Policy identifier", example = "ENTERPRISE_DEFAULT")
    private String policyId;

    @Schema(description = "Human-readable policy name", example = "Enterprise Default Policy")
    private String name;

    @Schema(description = "Minimum password length", example = "12", minimum = "8")
    @Builder.Default
    private int minLength = 12;

    @Schema(description = "Maximum password length", example = "128")
    @Builder.Default
    private int maxLength = 128;

    @Schema(description = "Require at least one uppercase letter")
    @Builder.Default
    private boolean requireUppercase = true;

    @Schema(description = "Require at least one lowercase letter")
    @Builder.Default
    private boolean requireLowercase = true;

    @Schema(description = "Require at least one digit")
    @Builder.Default
    private boolean requireDigit = true;

    @Schema(description = "Require at least one special character")
    @Builder.Default
    private boolean requireSpecialChar = true;

    @Schema(description = "Minimum number of uppercase letters required", example = "1")
    @Builder.Default
    private int minUppercase = 1;

    @Schema(description = "Minimum number of lowercase letters required", example = "1")
    @Builder.Default
    private int minLowercase = 1;

    @Schema(description = "Minimum number of digits required", example = "1")
    @Builder.Default
    private int minDigits = 1;

    @Schema(description = "Minimum number of special characters required", example = "1")
    @Builder.Default
    private int minSpecialChars = 1;

    @Schema(description = "Disallow commonly used passwords from breach databases")
    @Builder.Default
    private boolean preventCommonPasswords = true;

    @Schema(description = "Disallow sequential characters (e.g., abc, 123)")
    @Builder.Default
    private boolean preventSequentialChars = true;

    @Schema(description = "Disallow repeated character sequences (e.g., aaa, 111)")
    @Builder.Default
    private boolean preventRepeatedChars = true;

    @Schema(description = "Disallow keyboard patterns (e.g., qwerty, asdf)")
    @Builder.Default
    private boolean preventKeyboardPatterns = true;

    @Schema(description = "Minimum required entropy in bits", example = "50")
    @Builder.Default
    private double minEntropybits = 50.0;

    @Schema(description = "Minimum composite strength score (0–100) to pass validation", example = "60")
    @Builder.Default
    private int minimumAcceptableScore = 60;

    /**
     * Factory method: Enterprise-grade default policy.
     */
    public static PasswordPolicy enterpriseDefault() {
        return PasswordPolicy.builder()
                .policyId("ENTERPRISE_DEFAULT")
                .name("Enterprise Default Policy")
                .build();
    }

    /**
     * Factory method: Relaxed policy for legacy system integration.
     */
    public static PasswordPolicy legacy() {
        return PasswordPolicy.builder()
                .policyId("LEGACY")
                .name("Legacy Compatibility Policy")
                .minLength(8)
                .requireSpecialChar(false)
                .minEntropybits(30.0)
                .minimumAcceptableScore(40)
                .preventKeyboardPatterns(false)
                .build();
    }

    /**
     * Factory method: Strict policy for privileged/admin accounts.
     */
    public static PasswordPolicy privileged() {
        return PasswordPolicy.builder()
                .policyId("PRIVILEGED")
                .name("Privileged Account Policy")
                .minLength(16)
                .minUppercase(2)
                .minLowercase(2)
                .minDigits(2)
                .minSpecialChars(2)
                .minEntropybits(70.0)
                .minimumAcceptableScore(80)
                .build();
    }
}
