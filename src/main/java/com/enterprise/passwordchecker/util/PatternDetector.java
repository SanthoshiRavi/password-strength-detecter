package com.enterprise.passwordchecker.util;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Detects common password anti-patterns that reduce effective entropy.
 *
 * <p>Detected pattern types:
 * <ul>
 *   <li>{@code SEQUENTIAL_CHARS} — alphabetical or numeric runs (abc, 123)</li>
 *   <li>{@code REPEATED_CHARS} — three or more identical consecutive characters</li>
 *   <li>{@code KEYBOARD_PATTERN} — QWERTY row walks (qwerty, asdf, zxcv)</li>
 *   <li>{@code COMMON_WORD} — matches against a curated list of frequently used passwords</li>
 *   <li>{@code DATE_PATTERN} — year-like sequences (1900–2099)</li>
 *   <li>{@code LEET_SPEAK} — simple leet substitutions that offer minimal obfuscation</li>
 * </ul>
 */
@Component
public class PatternDetector {

    // ─── Regex patterns ───────────────────────────────────────────────────────

    private static final Pattern SEQUENTIAL_ALPHA =
            Pattern.compile("(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern SEQUENTIAL_NUMERIC =
            Pattern.compile("(?:012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)");

    private static final Pattern REPEATED_CHARS =
            Pattern.compile("(.)\\1{2,}");

    private static final Pattern DATE_PATTERN =
            Pattern.compile("(?:19|20)\\d{2}");

    private static final Pattern LEET_SPEAK =
            Pattern.compile("[4@][p][p][l][3]|[p][4][5][5][w][o0][r][d]|[4@][d][m][1][n]",
                    Pattern.CASE_INSENSITIVE);

    // ─── QWERTY keyboard rows and columns ────────────────────────────────────

    private static final List<String> KEYBOARD_SEQUENCES = List.of(
            "qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn",
            "qwert", "asdfg", "zxcvb", "yuiop", "hjkl",
            "1234567890", "!@#$%^&*()"
    );

    // ─── Common / breached passwords ─────────────────────────────────────────

    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "password", "123456", "password1", "qwerty", "abc123",
            "monkey", "1234567", "letmein", "dragon", "111111",
            "baseball", "iloveyou", "master", "sunshine", "ashley",
            "bailey", "passw0rd", "shadow", "superman", "michael",
            "football", "charlie", "donald", "password123", "admin",
            "welcome", "login", "hello", "princess", "starwars",
            "trustno1", "hunter", "pepper", "batman", "access"
    );

    /**
     * Analyses a password and returns a list of detected pattern identifiers.
     *
     * @param password the password to inspect
     * @return list of detected pattern codes (never null, may be empty)
     */
    public List<String> detect(String password) {
        if (password == null || password.isBlank()) {
            return List.of();
        }

        List<String> patterns = new ArrayList<>();
        String lower = password.toLowerCase();

        if (SEQUENTIAL_ALPHA.matcher(lower).find() || SEQUENTIAL_NUMERIC.matcher(password).find()) {
            patterns.add("SEQUENTIAL_CHARS");
        }
        if (REPEATED_CHARS.matcher(password).find()) {
            patterns.add("REPEATED_CHARS");
        }
        if (isKeyboardPattern(lower)) {
            patterns.add("KEYBOARD_PATTERN");
        }
        if (COMMON_PASSWORDS.contains(lower)) {
            patterns.add("COMMON_WORD");
        }
        if (DATE_PATTERN.matcher(password).find()) {
            patterns.add("DATE_PATTERN");
        }
        if (LEET_SPEAK.matcher(lower).find()) {
            patterns.add("LEET_SPEAK");
        }

        return patterns;
    }

    private boolean isKeyboardPattern(String lower) {
        for (String seq : KEYBOARD_SEQUENCES) {
            if (lower.contains(seq) || new StringBuilder(lower).reverse().toString().contains(seq)) {
                return true;
            }
        }
        return false;
    }
}
