package com.enterprise.passwordchecker.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Schema(name = "CrackTimeEstimate", description = "Estimated crack times under common attack scenarios")
public class CrackTimeEstimate {

    @Schema(description = "Estimated crack time — online attack, throttled (~10 guesses/sec)",
            example = "centuries")
    private String onlineThrottled;

    @Schema(description = "Estimated crack time — online attack, unthrottled (~100/sec)",
            example = "3 years")
    private String onlineUnthrottled;

    @Schema(description = "Estimated crack time — offline slow hash (~10k/sec)",
            example = "months")
    private String offlineSlowHash;

    @Schema(description = "Estimated crack time — offline fast hash, GPU (~10B/sec)",
            example = "minutes")
    private String offlineFastHash;

    @Schema(description = "Human-readable worst-case summary", example = "offline fast hash: minutes")
    private String summary;
}
