package com.enterprise.passwordchecker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

/**
 * Enterprise Password Strength Checker Application
 *
 * <p>Provides REST APIs to evaluate password strength, enforce password policies,
 * and offer actionable improvement suggestions using industry-standard libraries.
 *
 * @author Enterprise Security Team
 * @version 1.0.0
 */
@SpringBootApplication
@EnableCaching
public class PasswordStrengthCheckerApplication {

    public static void main(String[] args) {
        SpringApplication.run(PasswordStrengthCheckerApplication.class, args);
    }
}
