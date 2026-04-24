package com.enterprise.passwordchecker.dto;

import com.enterprise.passwordchecker.model.PasswordStrength;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(name = "BulkPasswordStrengthResponse", description = "Aggregated results for a batch password evaluation")
public class BulkPasswordStrengthResponse {

    @Schema(description = "Number of passwords evaluated", example = "10")
    private int totalEvaluated;

    @Schema(description = "Number of passwords that passed the policy", example = "7")
    private int policyCompliantCount;

    @Schema(description = "Number of passwords that failed the policy", example = "3")
    private int policyViolationCount;

    @Schema(description = "Average composite score across all passwords", example = "61.5")
    private double averageScore;

    @Schema(description = "Individual evaluation results")
    private List<PasswordStrengthResponse> results;

    @Schema(description = "Score distribution by strength level")
    private Map<PasswordStrength, Long> strengthDistribution;

    @Schema(description = "ISO 8601 timestamp of the batch evaluation")
    private Instant evaluatedAt;
}
