package com.enterprise.passwordchecker.util;

import org.springframework.stereotype.Component;

/**
 * Calculates Shannon entropy for a password string.
 *
 * <p>Entropy is computed as:
 * <pre>H = -Σ p(c) × log₂(p(c))</pre>
 * where {@code p(c)} is the probability of character {@code c} appearing in the password.
 *
 * <p>Additionally estimates character-pool entropy based on the character classes
 * present in the password.
 */
@Component
public class EntropyCalculator {

    /**
     * Calculates the Shannon entropy of the given password in bits.
     *
     * @param password the password to analyse (must not be null)
     * @return Shannon entropy in bits; 0.0 for blank input
     */
    public double calculate(String password) {
        if (password == null || password.isEmpty()) {
            return 0.0;
        }

        int[] freq = new int[128];
        int nonAscii = 0;

        for (char c : password.toCharArray()) {
            if (c < 128) {
                freq[c]++;
            } else {
                nonAscii++;
            }
        }

        double len = password.length();
        double entropy = 0.0;

        for (int count : freq) {
            if (count > 0) {
                double p = count / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }

        // Non-ASCII characters expand the effective character pool
        if (nonAscii > 0) {
            double p = nonAscii / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }

        // Scale by log₂(pool size) × length to normalise to a per-character estimate
        double poolSize = estimatePoolSize(password);
        double poolEntropy = password.length() * (Math.log(poolSize) / Math.log(2));

        // Return the minimum of Shannon entropy (actual) and pool entropy (theoretical upper bound)
        return Math.min(entropy * password.length(), poolEntropy);
    }

    /**
     * Estimates the size of the character pool used by the password.
     *
     * <p>Character pools:
     * <ul>
     *   <li>Lowercase letters: 26</li>
     *   <li>Uppercase letters: 26</li>
     *   <li>Digits: 10</li>
     *   <li>Special ASCII characters: 32</li>
     *   <li>Non-ASCII characters: 128 (conservative estimate)</li>
     * </ul>
     */
    public int estimatePoolSize(String password) {
        boolean hasLower = false, hasUpper = false, hasDigit = false,
                hasSpecial = false, hasNonAscii = false;

        for (char c : password.toCharArray()) {
            if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else if (c > 127) hasNonAscii = true;
            else hasSpecial = true;
        }

        int pool = 0;
        if (hasLower) pool += 26;
        if (hasUpper) pool += 26;
        if (hasDigit) pool += 10;
        if (hasSpecial) pool += 32;
        if (hasNonAscii) pool += 128;

        return Math.max(pool, 1);
    }
}
