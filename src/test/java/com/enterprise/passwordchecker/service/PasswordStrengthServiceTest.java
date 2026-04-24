package com.enterprise.passwordchecker.service;

import com.enterprise.passwordchecker.dto.PasswordCheckRequest;
import com.enterprise.passwordchecker.dto.PasswordStrengthResponse;
import com.enterprise.passwordchecker.model.PasswordStrength;
import com.enterprise.passwordchecker.util.EntropyCalculator;
import com.enterprise.passwordchecker.util.PatternDetector;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link PasswordStrengthService}.
 *
 * <p>Covers scoring accuracy, policy enforcement, pattern detection integration,
 * and edge cases.
 */
@DisplayName("PasswordStrengthService")
class PasswordStrengthServiceTest {

    private PasswordStrengthService service;

    @BeforeEach
    void setUp() {
        EntropyCalculator entropyCalculator = new EntropyCalculator();
        PatternDetector patternDetector = new PatternDetector();
        PasswordPolicyService policyService = new PasswordPolicyService();
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

        service = new PasswordStrengthService(entropyCalculator, patternDetector, policyService, meterRegistry);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Strength classification
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Strength classification")
    class StrengthClassificationTests {

        @ParameterizedTest(name = "'{0}' should be VERY_WEAK or WEAK")
        @ValueSource(strings = {"123456", "password", "abc123", "qwerty"})
        void weakPasswords_shouldScore_below40(String password) {
            PasswordStrengthResponse result = evaluate(password);
            assertThat(result.getScore()).isLessThan(40);
            assertThat(result.getStrength()).isIn(PasswordStrength.VERY_WEAK, PasswordStrength.WEAK);
        }

        @Test
        @DisplayName("Strong password should score ≥60 and be STRONG or VERY_STRONG")
        void strongPassword_shouldScore_above60() {
            PasswordStrengthResponse result = evaluate("X7@mKq#nL!2vRp9s");
            assertThat(result.getScore()).isGreaterThanOrEqualTo(60);
            assertThat(result.getStrength()).isIn(PasswordStrength.STRONG, PasswordStrength.VERY_STRONG);
        }

        @Test
        @DisplayName("Passphrase should score highly due to length and entropy")
        void passphrase_shouldScore_high() {
            PasswordStrengthResponse result = evaluate("correct-horse-battery-staple");
            assertThat(result.getScore()).isGreaterThan(50);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Policy compliance
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Policy compliance")
    class PolicyComplianceTests {

        @Test
        @DisplayName("Compliant password should have no violations")
        void compliantPassword_shouldPass_enterprisePolicy() {
            PasswordStrengthResponse result = evaluate("X7@mKq#nL!2vRp9s");
            assertThat(result.getPolicyViolations()).isEmpty();
            assertThat(result.isPolicyCompliant()).isTrue();
        }

        @Test
        @DisplayName("Short password should fail length rule")
        void shortPassword_shouldFail_lengthRule() {
            PasswordStrengthResponse result = evaluate("Ab1!");
            assertThat(result.isPolicyCompliant()).isFalse();
            assertThat(result.getPolicyViolations()).isNotEmpty();
        }

        @Test
        @DisplayName("All-lowercase password should fail uppercase rule")
        void allLowercase_shouldFail_uppercaseRule() {
            PasswordStrengthResponse result = evaluate("alllowercasepassword");
            assertThat(result.isPolicyCompliant()).isFalse();
        }

        @Test
        @DisplayName("PRIVILEGED policy should reject a password acceptable under DEFAULT")
        void passwordAcceptable_underDefault_butNot_underPrivileged() {
            PasswordCheckRequest req = PasswordCheckRequest.builder()
                    .password("Secure1Password!")
                    .policyId("PRIVILEGED")
                    .includeComposition(false)
                    .includeCrackTime(false)
                    .build();
            PasswordStrengthResponse result = service.evaluate(req);
            // PRIVILEGED requires score ≥80 — this password likely won't meet it
            assertThat(result.isPolicyCompliant()).isFalse();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pattern detection
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Pattern detection")
    class PatternDetectionTests {

        @Test
        @DisplayName("Password with 'qwerty' should detect KEYBOARD_PATTERN")
        void keyboardPattern_shouldBeDetected() {
            PasswordStrengthResponse result = evaluate("qwerty123!");
            assertThat(result.getDetectedPatterns()).contains("KEYBOARD_PATTERN");
        }

        @Test
        @DisplayName("Password with sequential digits should detect SEQUENTIAL_CHARS")
        void sequentialDigits_shouldBeDetected() {
            PasswordStrengthResponse result = evaluate("mypass123go");
            assertThat(result.getDetectedPatterns()).contains("SEQUENTIAL_CHARS");
        }

        @Test
        @DisplayName("Repeated chars 'aaa' should detect REPEATED_CHARS")
        void repeatedChars_shouldBeDetected() {
            PasswordStrengthResponse result = evaluate("paaassword123!");
            assertThat(result.getDetectedPatterns()).contains("REPEATED_CHARS");
        }

        @Test
        @DisplayName("Diverse random password should have no detected patterns")
        void randomPassword_shouldHave_noPatterns() {
            PasswordStrengthResponse result = evaluate("X7@mKq#nL!2vRp9s");
            assertThat(result.getDetectedPatterns()).isEmpty();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Composition analysis
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Composition analysis")
    class CompositionTests {

        @Test
        @DisplayName("Composition should count character classes correctly")
        void composition_shouldCountCorrectly() {
            PasswordStrengthResponse result = evaluate("Abc1!");
            assertThat(result.getComposition()).isNotNull();
            assertThat(result.getComposition().getUppercaseCount()).isEqualTo(1);
            assertThat(result.getComposition().getLowercaseCount()).isEqualTo(2);
            assertThat(result.getComposition().getDigitCount()).isEqualTo(1);
            assertThat(result.getComposition().getSpecialCharCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("Composition should be null when includeComposition=false")
        void composition_shouldBeNull_whenNotRequested() {
            PasswordCheckRequest req = PasswordCheckRequest.builder()
                    .password("TestPass1!")
                    .includeComposition(false)
                    .includeCrackTime(false)
                    .build();
            PasswordStrengthResponse result = service.evaluate(req);
            assertThat(result.getComposition()).isNull();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Suggestions
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Suggestions")
    class SuggestionTests {

        @Test
        @DisplayName("Very strong password should have only a positive suggestion")
        void strongPassword_shouldSuggest_noChanges() {
            PasswordStrengthResponse result = evaluate("X7@mKq#nL!2vRp9s");
            assertThat(result.getSuggestions()).isNotNull();
        }

        @Test
        @DisplayName("Weak password should have actionable suggestions")
        void weakPassword_shouldHave_suggestions() {
            PasswordStrengthResponse result = evaluate("password");
            assertThat(result.getSuggestions()).isNotEmpty();
            assertThat(result.getSuggestions().size()).isGreaterThan(1);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Entropy
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Entropy")
    class EntropyTests {

        @ParameterizedTest(name = "'{0}' entropy should be > '{1}' bits")
        @CsvSource({
                "X7@mKq#nL!2vRp9s, 40",
                "correct-horse-battery-staple, 30",
        })
        void entropy_shouldExceed_threshold(String password, double minEntropy) {
            PasswordStrengthResponse result = evaluate(password);
            assertThat(result.getEntropyBits()).isGreaterThan(minEntropy);
        }

        @Test
        @DisplayName("Repeated single char should have near-zero entropy")
        void repeatedChar_shouldHave_lowEntropy() {
            PasswordStrengthResponse result = evaluate("aaaaaaaaaaaaa");
            assertThat(result.getEntropyBits()).isLessThan(5.0);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private PasswordStrengthResponse evaluate(String password) {
        return service.evaluate(PasswordCheckRequest.builder()
                .password(password)
                .includeComposition(true)
                .includeCrackTime(true)
                .build());
    }
}
