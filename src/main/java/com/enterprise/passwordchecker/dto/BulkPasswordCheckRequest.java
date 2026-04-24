package com.enterprise.passwordchecker.dto;

import com.enterprise.passwordchecker.model.PasswordStrength;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
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
@Schema(name = "BulkPasswordCheckRequest", description = "Payload for evaluating multiple passwords in one request")
public class BulkPasswordCheckRequest {

    @Schema(
            description = "List of password evaluation requests (max 50 per batch).",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    @NotEmpty(message = "Password list must not be empty")
    @Size(max = 50, message = "Batch size cannot exceed 50 passwords")
    @Valid
    private List<PasswordCheckRequest> passwords;

    @Schema(description = "Policy preset applied uniformly to all passwords in the batch.",
            example = "ENTERPRISE_DEFAULT")
    private String policyId;
}
