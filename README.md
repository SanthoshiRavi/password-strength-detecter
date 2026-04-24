# 🔐 Enterprise Password Strength Checker API

A production-grade Spring Boot REST API for evaluating password strength, enforcing configurable
security policies, and providing actionable improvement guidance.

---

## 🏗️ Architecture Overview

```
src/main/java/com/enterprise/passwordchecker/
├── PasswordStrengthCheckerApplication.java   # Entry point
├── config/
│   └── OpenApiConfig.java                    # Swagger / OpenAPI 3.0 config
├── controller/
│   └── PasswordStrengthController.java       # REST endpoints
├── service/
│   ├── PasswordStrengthService.java          # Core evaluation engine
│   └── PasswordPolicyService.java            # Policy resolution & Passay validation
├── model/
│   ├── PasswordStrength.java                 # Strength level enum (VERY_WEAK → VERY_STRONG)
│   └── PasswordPolicy.java                   # Policy configuration model
├── dto/
│   ├── PasswordCheckRequest.java             # Single evaluation request
│   ├── BulkPasswordCheckRequest.java         # Batch evaluation request
│   ├── PasswordStrengthResponse.java         # Evaluation result
│   ├── BulkPasswordStrengthResponse.java     # Batch result with aggregate metrics
│   ├── CharacterComposition.java             # Character breakdown
│   ├── CrackTimeEstimate.java                # Attack scenario crack times
│   └── ErrorResponse.java                    # Standardised error envelope
├── util/
│   ├── EntropyCalculator.java                # Shannon entropy analysis
│   └── PatternDetector.java                  # Anti-pattern detection
└── exception/
    └── GlobalExceptionHandler.java           # Centralised error handling
```

---

## 🚀 Getting Started

### Prerequisites
- Java 17+
- Maven 3.8+

### Run locally

```bash
mvn spring-boot:run
```

### Build JAR

```bash
mvn clean package
java -jar target/password-strength-checker-1.0.0.jar
```

---

## 📖 API Documentation

Once running, open:

| Resource | URL |
|----------|-----|
| **Swagger UI** | http://localhost:8080/swagger-ui.html |
| **OpenAPI JSON** | http://localhost:8080/api-docs |
| **Actuator** | http://localhost:8080/actuator |
| **Prometheus** | http://localhost:8080/actuator/prometheus |

---

## 🔗 Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/password/check` | Evaluate a single password |
| `POST` | `/api/v1/password/check/bulk` | Evaluate up to 50 passwords |
| `GET` | `/api/v1/password/policies` | List all policy presets |
| `GET` | `/api/v1/password/policies/{id}` | Get a specific policy |
| `GET` | `/api/v1/password/health` | Liveness probe |

---

## 📋 Example: Single Evaluation

**Request**
```json
POST /api/v1/password/check
{
  "password": "MyS3cur3P@ssw0rd!",
  "username": "john.doe",
  "policyId": "ENTERPRISE_DEFAULT",
  "includeComposition": true,
  "includeCrackTime": true
}
```

**Response**
```json
{
  "score": 74,
  "strength": "STRONG",
  "policyCompliant": true,
  "appliedPolicyId": "ENTERPRISE_DEFAULT",
  "policyViolations": [],
  "suggestions": ["Your password meets all requirements. No changes needed."],
  "composition": {
    "totalLength": 17,
    "uppercaseCount": 2,
    "lowercaseCount": 9,
    "digitCount": 3,
    "specialCharCount": 3,
    "whitespaceCount": 0,
    "uniqueCharCount": 15,
    "asciiOnly": true
  },
  "crackTime": {
    "onlineThrottled": "centuries",
    "onlineUnthrottled": "3 years",
    "offlineSlowHash": "months",
    "offlineFastHash": "minutes",
    "summary": "offline fast hash: minutes"
  },
  "entropyBits": 62.4,
  "detectedPatterns": [],
  "evaluatedAt": "2024-01-15T10:30:00Z",
  "apiVersion": "1.0.0"
}
```

---

## 🛡️ Policy Presets

| ID | Min Length | Score Threshold | Target Use Case |
|----|-----------|----------------|-----------------|
| `ENTERPRISE_DEFAULT` | 12 | 60 | Standard user accounts |
| `LEGACY` | 8 | 40 | Legacy system integration |
| `PRIVILEGED` | 16 | 80 | Admin / privileged accounts |

---

## 📊 Scoring Model

The composite score (0–100) is derived from:

| Component | Weight | Description |
|-----------|--------|-------------|
| Entropy | 40 pts | Shannon entropy analysis |
| zxcvbn | 40 pts | Dropbox realistic-attack model |
| Length bonus | 10 pts | Extra credit for long passwords |
| Pattern penalties | −5 pts each | Keyboard walks, sequences, repeats |

---

## ⚙️ Libraries Used

| Library | Purpose |
|---------|---------|
| **Spring Boot 3.2** | Web framework |
| **SpringDoc OpenAPI 2.3** | Swagger UI & OpenAPI 3.0 spec |
| **Passay 1.6** | Rules-based password policy enforcement |
| **zxcvbn4j 1.8** | Realistic crack-time estimation |
| **Micrometer + Prometheus** | Operational metrics |
| **Lombok** | Boilerplate reduction |

---

## 🧪 Running Tests

```bash
mvn test
```

---

## 🔒 Security Considerations

- Passwords are **never logged** at any log level
- Passwords are evaluated **in-memory only** and never persisted
- Evaluation timestamps use **server-side UTC** (not client-supplied)
- All inputs are **validated and size-bounded** before processing
- Correlation IDs enable **distributed tracing** without leaking sensitive data
