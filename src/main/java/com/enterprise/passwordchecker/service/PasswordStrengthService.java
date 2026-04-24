package com.enterprise.passwordchecker.service;

import com.enterprise.passwordchecker.dto.*;
import com.enterprise.passwordchecker.model.PasswordPolicy;
import com.enterprise.passwordchecker.model.PasswordStrength;
import com.enterprise.passwordchecker.util.EntropyCalculator;
import com.enterprise.passwordchecker.util.PatternDetector;
import com.nulabinc.zxcvbn.AttackTimes;
import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Core service for password strength evaluation.
 *
 * <p>Combines entropy analysis, pattern detection, policy enforcement, and
 * zxcvbn-based scoring to produce a comprehensive strength report.
 *
 * <p>Passwords are NEVER logged at any log level.
 */
@Slf4j
@Service
public class PasswordStrengthService {

    private static final String API_VERSION = "1.0.0";

    private final Zxcvbn zxcvbn = new Zxcvbn();
    private final EntropyCalculator entropyCalculator;
    private final PatternDetector patternDetector;
    private final PasswordPolicyService policyService;

    private final Counter evaluationCounter;
    private final Counter policyViolationCounter;
    private final Timer evaluationTimer;

    @Value("${app.version:1.0.0}")
    private String appVersion;

    public PasswordStrengthService(
            EntropyCalculator entropyCalculator,
            PatternDetector patternDetector,
            PasswordPolicyService policyService,
            MeterRegistry meterRegistry) {
        this.entropyCalculator = entropyCalculator;
        this.patternDetector = patternDetector;
        this.policyService = policyService;

        this.evaluationCounter = Counter.builder("password.evaluations.total")
                .description("Total number of password evaluations")
                .register(meterRegistry);
        this.policyViolationCounter = Counter.builder("password.policy.violations.total")
                .description("Total number of policy violations detected")
                .register(meterRegistry);
        this.evaluationTimer = Timer.builder("password.evaluation.duration")
                .description("Time taken to evaluate a password")
                .register(meterRegistry);
    }

    /**
     * Evaluates a single password against the specified (or default) policy.
     *
     * @param request the evaluation request
     * @return comprehensive strength report
     */
    public PasswordStrengthResponse evaluate(PasswordCheckRequest request) {
        return evaluationTimer.record(() -> doEvaluate(request));
    }

    /**
     * Evaluates a batch of passwords and returns aggregated results.
     *
     * @param request bulk evaluation request
     * @return aggregated batch result
     */
    public BulkPasswordStrengthResponse evaluateBulk(BulkPasswordCheckRequest request) {
        log.info("Starting bulk evaluation of {} passwords with policy={}",
                request.getPasswords().size(), request.getPolicyId());

        String effectivePolicyId = Optional.ofNullable(request.getPolicyId())
                .orElse("ENTERPRISE_DEFAULT");

        List<PasswordStrengthResponse> results = request.getPasswords().stream()
                .map(pr -> {
                    PasswordCheckRequest enriched = PasswordCheckRequest.builder()
                            .password(pr.getPassword())
                            .username(pr.getUsername())
                            .policyId(effectivePolicyId)
                            .includeComposition(pr.isIncludeComposition())
                            .includeCrackTime(pr.isIncludeCrackTime())
                            .build();
                    return evaluate(enriched);
                })
                .collect(Collectors.toList());

        long compliant = results.stream().filter(PasswordStrengthResponse::isPolicyCompliant).count();
        double avgScore = results.stream().mapToInt(PasswordStrengthResponse::getScore).average().orElse(0.0);
        Map<PasswordStrength, Long> distribution = results.stream()
                .collect(Collectors.groupingBy(PasswordStrengthResponse::getStrength, Collectors.counting()));

        log.info("Bulk evaluation complete. compliant={}/{}, avgScore={:.1f}",
                compliant, results.size(), avgScore);

        return BulkPasswordStrengthResponse.builder()
                .totalEvaluated(results.size())
                .policyCompliantCount((int) compliant)
                .policyViolationCount((int) (results.size() - compliant))
                .averageScore(Math.round(avgScore * 10.0) / 10.0)
                .results(results)
                .strengthDistribution(distribution)
                .evaluatedAt(Instant.now())
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private implementation
    // ─────────────────────────────────────────────────────────────────────────

    private PasswordStrengthResponse doEvaluate(PasswordCheckRequest request) {
        evaluationCounter.increment();

        String password = request.getPassword();
        PasswordPolicy policy = policyService.resolve(request.getPolicyId());

        // 1. Entropy analysis
        double entropy = entropyCalculator.calculate(password);

        // 2. Pattern detection
        List<String> detectedPatterns = patternDetector.detect(password);

        // 3. Zxcvbn scoring (Dropbox algorithm)
        List<String> userInputs = buildUserInputs(request.getUsername());
        Strength zxcvbnStrength = zxcvbn.measure(password, userInputs);
        int zxcvbnScore = zxcvbnStrength.getScore(); // 0–4

        // 4. Composite scoring
        int compositeScore = computeCompositeScore(password, entropy, zxcvbnScore, detectedPatterns, policy);
        PasswordStrength strengthLevel = PasswordStrength.fromScore(compositeScore);

        // 5. Policy validation
        List<String> violations = policyService.validate(password, policy);
        boolean policyCompliant = violations.isEmpty() && compositeScore >= policy.getMinimumAcceptableScore();

        if (!policyCompliant) {
            policyViolationCounter.increment();
        }

        // 6. Suggestions
        List<String> suggestions = buildSuggestions(password, violations, detectedPatterns, compositeScore, policy);

        // 7. Composition (optional)
        CharacterComposition composition = null;
        if (request.isIncludeComposition()) {
            composition = analyzeComposition(password);
        }

        // 8. Crack time (optional)
        CrackTimeEstimate crackTime = null;
        if (request.isIncludeCrackTime()) {
            crackTime = buildCrackTimeEstimate(zxcvbnStrength);
        }

        log.debug("Password evaluated: score={}, strength={}, policyCompliant={}, policyId={}",
                compositeScore, strengthLevel, policyCompliant, policy.getPolicyId());

        return PasswordStrengthResponse.builder()
                .score(compositeScore)
                .strength(strengthLevel)
                .policyCompliant(policyCompliant)
                .appliedPolicyId(policy.getPolicyId())
                .policyViolations(violations)
                .suggestions(suggestions)
                .composition(composition)
                .crackTime(crackTime)
                .entropyBits(Math.round(entropy * 10.0) / 10.0)
                .detectedPatterns(detectedPatterns)
                .evaluatedAt(Instant.now())
                .apiVersion(appVersion)
                .build();
    }

    private int computeCompositeScore(String password, double entropy, int zxcvbnScore,
                                      List<String> patterns, PasswordPolicy policy) {
        // Entropy component (0–40 points, capped at 80 bits)
        double entropyComponent = Math.min(entropy / 80.0, 1.0) * 40.0;

        // Zxcvbn component (0–40 points, scale 0–4 → 0–40)
        double zxcvbnComponent = (zxcvbnScore / 4.0) * 40.0;

        // Length bonus (0–10 points)
        double lengthBonus = computeLengthBonus(password.length(), policy);

        // Pattern penalty (–5 points each, max –20)
        double patternPenalty = Math.min(patterns.size() * 5.0, 20.0);

        double raw = entropyComponent + zxcvbnComponent + lengthBonus - patternPenalty;
        return (int) Math.max(0, Math.min(100, Math.round(raw)));
    }

    private double computeLengthBonus(int length, PasswordPolicy policy) {
        int minLen = policy.getMinLength();
        if (length <= minLen) return 0;
        if (length >= minLen + 16) return 10;
        return ((double)(length - minLen) / 16.0) * 10.0;
    }

    private CharacterComposition analyzeComposition(String password) {
        int upper = 0, lower = 0, digit = 0, special = 0, space = 0;
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) upper++;
            else if (Character.isLowerCase(c)) lower++;
            else if (Character.isDigit(c)) digit++;
            else if (Character.isWhitespace(c)) space++;
            else special++;
        }
        boolean asciiOnly = password.chars().allMatch(c -> c < 128);
        long unique = password.chars().distinct().count();

        return CharacterComposition.builder()
                .totalLength(password.length())
                .uppercaseCount(upper)
                .lowercaseCount(lower)
                .digitCount(digit)
                .specialCharCount(special)
                .whitespaceCount(space)
                .uniqueCharCount((int) unique)
                .asciiOnly(asciiOnly)
                .build();
    }

    private CrackTimeEstimate buildCrackTimeEstimate(Strength zxcvbnStrength) {
        AttackTimes.CrackTimesDisplay crackTimes = zxcvbnStrength.getCrackTimesDisplay();
        return CrackTimeEstimate.builder()
                .onlineThrottled(crackTimes.getOnlineThrottling100perHour())
                .onlineUnthrottled(crackTimes.getOnlineNoThrottling10perSecond())
                .offlineSlowHash(crackTimes.getOfflineSlowHashing1e4perSecond())
                .offlineFastHash(crackTimes.getOfflineFastHashing1e10PerSecond())
                .summary("offline fast hash: " + crackTimes.getOfflineFastHashing1e10PerSecond())
                .build();
    }

    private List<String> buildSuggestions(String password, List<String> violations,
                                          List<String> patterns, int score, PasswordPolicy policy) {
        List<String> suggestions = new ArrayList<>(violations);

        if (score < 40 && password.length() < policy.getMinLength() + 4) {
            suggestions.add("Consider using a passphrase of 4+ random words for significantly better security.");
        }
        if (patterns.contains("SEQUENTIAL_CHARS")) {
            suggestions.add("Avoid sequential characters like 'abc' or '123'.");
        }
        if (patterns.contains("KEYBOARD_PATTERN")) {
            suggestions.add("Avoid keyboard walk patterns like 'qwerty' or 'asdf'.");
        }
        if (patterns.contains("REPEATED_CHARS")) {
            suggestions.add("Avoid repeated character sequences like 'aaa' or '111'.");
        }
        if (patterns.contains("COMMON_WORD")) {
            suggestions.add("Avoid dictionary words. Mix in numbers and special characters.");
        }
        if (score < 60 && violations.isEmpty()) {
            suggestions.add("Increase password length to at least " + (policy.getMinLength() + 4) + " characters.");
            suggestions.add("Add a mix of uppercase, lowercase, digits, and symbols.");
        }
        return suggestions.isEmpty()
                ? List.of("Your password meets all requirements. No changes needed.")
                : suggestions;
    }

    private List<String> buildUserInputs(String username) {
        List<String> inputs = new ArrayList<>();
        if (username != null && !username.isBlank()) {
            inputs.add(username);
        }
        return inputs;
    }
}
