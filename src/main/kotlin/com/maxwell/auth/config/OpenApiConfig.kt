package com.maxwell.auth.config

import io.swagger.v3.oas.models.Components
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Contact
import io.swagger.v3.oas.models.info.Info
import io.swagger.v3.oas.models.security.SecurityRequirement
import io.swagger.v3.oas.models.security.SecurityScheme
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class OpenApiConfig {

    @Bean
    fun openAPI(): OpenAPI = OpenAPI()
        .info(
            Info()
                .title("Auth Microservice API")
                .description(
                    "Authentication microservice with JWT, OAuth2, role-based access control, " +
                        "and fraud detection (rate limiting, IP blocking, account lockout)."
                )
                .version("1.0.0")
                .contact(
                    Contact()
                        .name("Maxwell Aboagye")
                        .url("https://github.com/maxxy21/auth-microservice")
                )
        )
        .addSecurityItem(SecurityRequirement().addList("Bearer Authentication"))
        .components(
            Components().addSecuritySchemes(
                "Bearer Authentication",
                SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")
                    .description("Paste the access token returned by /api/auth/login")
            )
        )
}
