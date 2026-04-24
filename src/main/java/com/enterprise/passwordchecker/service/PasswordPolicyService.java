package com.enterprise.passwordchecker.service;

import com.enterprise.passwordchecker.model.PasswordPolicy;
import lombok.extern.slf4j.Slf4j;
import org.passay.*;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Resolves password policies and validates passwords against them.
 *
 * <p>Uses Passay for rules-based validation and supports three built-in policy
 * presets (ENTERPRISE_DEFAULT, LEGACY, PRIVILEGED). Custom policy injection
 * can be added by extending the {@code policyRegistry} map.
 */
@Slf4j
@Service
public class PasswordPolicyService {

    private static final String DEFAULT_POLICY_ID = "ENTERPRISE_DEFAULT";

    private final Map<String, PasswordPolicy> policyRegistry;

    public PasswordPolicyService() {
        policyRegistry = new HashMap<>();
        policyRegistry.put("ENTERPRISE_DEFAULT", PasswordPolicy.enterpriseDefault());
        policyRegistry.put("LEGACY", PasswordPolicy.legacy());
        policyRegistry.put("PRIVILEGED", PasswordPolicy.privileged());
    }

    /**
     * Resolves a {@link PasswordPolicy} by its identifier.
     *
     * @param policyId the policy key (nullable — falls back to ENTERPRISE_DEFAULT)
     * @return the resolved policy
     */
    public PasswordPolicy resolve(String policyId) {
        String key = (policyId != null && !policyId.isBlank()) ? policyId : DEFAULT_POLICY_ID;
        PasswordPolicy policy = policyRegistry.get(key.toUpperCase());
        if (policy == null) {
            log.warn("Unknown policyId '{}'. Falling back to ENTERPRISE_DEFAULT.", key);
            policy = policyRegistry.get(DEFAULT_POLICY_ID);
        }
        return policy;
    }

    /**
     * Retrieves all registered policy descriptors (without sensitive rule detail).
     */
    public Collection<PasswordPolicy> listPolicies() {
        return Collections.unmodifiableCollection(policyRegistry.values());
    }

    /**
     * Validates a password against a policy and returns human-readable violation messages.
     *
     * @param password plain-text password
     * @param policy   the policy to enforce
     * @return list of violation messages (empty if compliant)
     */
    public List<String> validate(String password, PasswordPolicy policy) {
        List<Rule> rules = buildRules(policy);
        PasswordValidator validator = new PasswordValidator(rules);
        RuleResult result = validator.validate(new PasswordData(password));

        if (result.isValid()) {
            return Collections.emptyList();
        }

        return validator.getMessages(result).stream()
                .map(this::humanize)
                .distinct()
                .collect(Collectors.toList());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Rule construction
    // ─────────────────────────────────────────────────────────────────────────

    private List<Rule> buildRules(PasswordPolicy policy) {
        List<Rule> rules = new ArrayList<>();

        // Length
        rules.add(new LengthRule(policy.getMinLength(), policy.getMaxLength()));

        // Character class requirements
        CharacterCharacteristicsRule charRule = new CharacterCharacteristicsRule();
        int requiredCharacteristics = 0;

        if (policy.isRequireUppercase()) {
            charRule.getRules().add(new CharacterRule(EnglishCharacterData.UpperCase, policy.getMinUppercase()));
            requiredCharacteristics++;
        }
        if (policy.isRequireLowercase()) {
            charRule.getRules().add(new CharacterRule(EnglishCharacterData.LowerCase, policy.getMinLowercase()));
            requiredCharacteristics++;
        }
        if (policy.isRequireDigit()) {
            charRule.getRules().add(new CharacterRule(EnglishCharacterData.Digit, policy.getMinDigits()));
            requiredCharacteristics++;
        }
        if (policy.isRequireSpecialChar()) {
            charRule.getRules().add(new CharacterRule(EnglishCharacterData.Special, policy.getMinSpecialChars()));
            requiredCharacteristics++;
        }

        if (requiredCharacteristics > 0) {
            charRule.setNumberOfCharacteristics(requiredCharacteristics);
            rules.add(charRule);
        }

        // Repeated characters
        if (policy.isPreventRepeatedChars()) {
            rules.add(new RepeatCharactersRule(3));
        }

        // Sequential characters (alphabetical and numerical)
        if (policy.isPreventSequentialChars()) {
            rules.add(new IllegalSequenceRule(EnglishSequenceData.Alphabetical, 4, false));
            rules.add(new IllegalSequenceRule(EnglishSequenceData.Numerical, 4, false));
        }

        // Keyboard patterns (QWERTY)
        if (policy.isPreventKeyboardPatterns()) {
            rules.add(new IllegalSequenceRule(EnglishSequenceData.USQwerty, 4, false));
        }

        // Whitespace
        rules.add(new WhitespaceRule());

        return rules;
    }

    /**
     * Converts Passay's terse messages to more actionable English.
     */
    private String humanize(String message) {
        return message
                .replace("Password must be", "Must be")
                .replace("Password must contain", "Must contain")
                .replace("Password contains", "Remove")
                .replace("at least 1 uppercase character", "at least 1 uppercase letter (A–Z)")
                .replace("at least 1 lowercase character", "at least 1 lowercase letter (a–z)")
                .replace("at least 1 digit character", "at least 1 digit (0–9)")
                .replace("at least 1 special character", "at least 1 special character (e.g. !@#$%)");
    }
}
