package com.enterprise.passwordchecker.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Enumeration of password strength levels based on composite scoring.
 *
 * <p>Each level maps to a score range and carries metadata for UI rendering
 * and policy enforcement decisions.
 */
@Getter
@RequiredArgsConstructor
@Schema(description = "Password strength classification")
public enum PasswordStrength {

    @Schema(description = "Score 0–19: Trivially cracked. Immediate rejection recommended.")
    VERY_WEAK(0, 19, "Very Weak", "danger", "#FF3B30"),

    @Schema(description = "Score 20–39: Crackable within hours. Should be rejected for sensitive accounts.")
    WEAK(20, 39, "Weak", "warning", "#FF9500"),

    @Schema(description = "Score 40–59: Adequate for low-risk contexts. Acceptable with MFA.")
    FAIR(40, 59, "Fair", "info", "#FFCC00"),

    @Schema(description = "Score 60–79: Suitable for most standard use cases.")
    STRONG(60, 79, "Strong", "success", "#34C759"),

    @Schema(description = "Score 80–100: Highly resistant to all known attack vectors.")
    VERY_STRONG(80, 100, "Very Strong", "primary", "#007AFF");

    private final int minScore;
    private final int maxScore;
    private final String label;
    private final String cssClass;
    private final String hexColor;

    /**
     * Resolves a {@link PasswordStrength} level from a numeric score (0–100).
     *
     * @param score composite strength score
     * @return corresponding strength level
     */
    public static PasswordStrength fromScore(int score) {
        int clampedScore = Math.max(0, Math.min(100, score));
        for (PasswordStrength level : values()) {
            if (clampedScore >= level.minScore && clampedScore <= level.maxScore) {
                return level;
            }
        }
        return VERY_WEAK;
    }
}
