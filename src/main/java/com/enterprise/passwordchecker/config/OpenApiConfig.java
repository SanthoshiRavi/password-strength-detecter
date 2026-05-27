package com.enterprise.passwordchecker.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI 3.0 / Swagger configuration for the Password Strength Checker API.
 *
 * <p>Configures API metadata, server definitions, security schemes, and
 * documentation tags for the Swagger UI.
 */
@Configuration
public class OpenApiConfig {

    @Value("${app.version:1.0.0}")
    private String appVersion;

    @Value("${server.port:8080}")
    private String serverPort;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(buildApiInfo())
                .servers(buildServers())
                .tags(buildTags())
                .externalDocs(buildExternalDocs())
                .components(buildComponents());
    }

    private Info buildApiInfo() {
        return new Info()
                .title("Password Strength Checker API")
                .version(appVersion)
                .description("""
                        ## Enterprise Password Strength Checker
                        
                        A production-grade REST API for evaluating password strength, enforcing 
                        configurable security policies, and providing actionable improvement suggestions.
                        
                        ### Features
                        - **Multi-dimensional scoring**: Entropy, pattern detection, and policy compliance
                        - **Policy enforcement**: NIST 800-63B and OWASP-compliant rulesets
                        - **Breach detection**: Common password blacklist validation
                        - **Detailed feedback**: Specific, actionable improvement suggestions
                        - **Bulk evaluation**: Batch password checks for audit workflows
                        
                        ### Strength Levels
                        | Score | Level | Description |
                        |-------|-------|-------------|
                        | 0–19  | VERY_WEAK | Easily cracked in seconds |
                        | 20–39 | WEAK | Cracked in minutes to hours |
                        | 40–59 | FAIR | Adequate for low-risk contexts |
                        | 60–79 | STRONG | Suitable for most use cases |
                        | 80–100 | VERY_STRONG | Highly resistant to attacks |
                        """)
                .contact(new Contact()
                        .name("Enterprise Security Team")
                        .email("security@enterprise.com")
                        .url("https://security.enterprise.com"))
                .license(new License()
                        .name("Proprietary")
                        .url("https://enterprise.com/license"));
    }

    private List<Server> buildServers() {
        return List.of(

                new Server()
                        .url("http://13.235.2.214:8443")
                        .description("EC2 Deployment Server"),

                new Server()
                        .url("http://localhost:" + serverPort)
                        .description("Local Development"),

                new Server()
                        .url("https://api-staging.enterprise.com")
                        .description("Staging Environment"),

                new Server()
                        .url("https://api.enterprise.com")
                        .description("Production Environment")
        );
    }

    private List<Tag> buildTags() {
        return List.of(
                new Tag()
                        .name("Password Evaluation")
                        .description("Core password strength analysis and scoring"),
                new Tag()
                        .name("Policy Management")
                        .description("Password policy configuration and retrieval"),
                new Tag()
                        .name("Bulk Operations")
                        .description("Batch password evaluation for audit workflows"),
                new Tag()
                        .name("Health & Metrics")
                        .description("Application health checks and operational metrics")
        );
    }

    private ExternalDocumentation buildExternalDocs() {
        return new ExternalDocumentation()
                .description("Enterprise Security Documentation")
                .url("https://docs.enterprise.com/security/password-policy");
    }

    private Components buildComponents() {
        return new Components()
                .addSecuritySchemes("ApiKeyAuth",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name("X-API-Key")
                                .description("API key for service-to-service authentication"))
                .addSecuritySchemes("BearerAuth",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT Bearer token for user authentication"));
    }
}
