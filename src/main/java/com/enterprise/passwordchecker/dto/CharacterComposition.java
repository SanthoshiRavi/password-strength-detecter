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
@Schema(name = "CharacterComposition", description = "Breakdown of character types in the password")
public class CharacterComposition {

    @Schema(description = "Total character count", example = "16")
    private int totalLength;

    @Schema(description = "Number of uppercase letters", example = "3")
    private int uppercaseCount;

    @Schema(description = "Number of lowercase letters", example = "7")
    private int lowercaseCount;

    @Schema(description = "Number of digits", example = "3")
    private int digitCount;

    @Schema(description = "Number of special characters", example = "3")
    private int specialCharCount;

    @Schema(description = "Number of whitespace characters", example = "0")
    private int whitespaceCount;

    @Schema(description = "Unique character count (no duplicates)", example = "14")
    private int uniqueCharCount;

    @Schema(description = "True if password contains only ASCII characters")
    private boolean asciiOnly;
}
