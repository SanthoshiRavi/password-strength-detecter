package com.enterprise.passwordchecker.controller;

import com.enterprise.passwordchecker.dto.PasswordCheckRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for {@link PasswordStrengthController}.
 *
 * <p>Boots the full application context and exercises endpoints via MockMvc.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("PasswordStrengthController Integration Tests")
class PasswordStrengthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("POST /check — valid password returns 200 with score")
    void checkPassword_validRequest_returns200() throws Exception {
        PasswordCheckRequest request = PasswordCheckRequest.builder()
                .password("X7@mKq#nL!2vRp9s")
                .policyId("ENTERPRISE_DEFAULT")
                .includeComposition(true)
                .includeCrackTime(true)
                .build();

        mockMvc.perform(post("/api/v1/password/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.score").isNumber())
                .andExpect(jsonPath("$.strength").isString())
                .andExpect(jsonPath("$.policyCompliant").isBoolean())
                .andExpect(jsonPath("$.appliedPolicyId").value("ENTERPRISE_DEFAULT"))
                .andExpect(jsonPath("$.composition").exists())
                .andExpect(jsonPath("$.crackTime").exists())
                .andExpect(jsonPath("$.suggestions").isArray())
                .andExpect(jsonPath("$.entropyBits").isNumber());
    }

    @Test
    @DisplayName("POST /check — blank password returns 400")
    void checkPassword_blankPassword_returns400() throws Exception {
        PasswordCheckRequest request = PasswordCheckRequest.builder()
                .password("")
                .build();

        mockMvc.perform(post("/api/v1/password/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.fieldErrors.password").exists());
    }

    @Test
    @DisplayName("POST /check — invalid policyId returns 400")
    void checkPassword_invalidPolicy_returns400() throws Exception {
        PasswordCheckRequest request = PasswordCheckRequest.builder()
                .password("ValidPass1!")
                .policyId("INVALID_POLICY")
                .build();

        mockMvc.perform(post("/api/v1/password/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("GET /policies — returns all policies")
    void listPolicies_returnsAllPolicies() throws Exception {
        mockMvc.perform(get("/api/v1/password/policies"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(3))));
    }

    @Test
    @DisplayName("GET /policies/{id} — known policy returns 200")
    void getPolicy_knownId_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/password/policies/ENTERPRISE_DEFAULT"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.policyId").value("ENTERPRISE_DEFAULT"))
                .andExpect(jsonPath("$.minLength").value(12));
    }

    @Test
    @DisplayName("GET /health — returns UP")
    void health_returnsUp() throws Exception {
        mockMvc.perform(get("/api/v1/password/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }
}
