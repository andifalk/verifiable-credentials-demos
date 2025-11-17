package org.example.issuer

import io.swagger.v3.oas.annotations.OpenAPIDefinition
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType
import io.swagger.v3.oas.annotations.info.Info
import io.swagger.v3.oas.annotations.security.OAuthFlow
import io.swagger.v3.oas.annotations.security.OAuthFlows
import io.swagger.v3.oas.annotations.security.OAuthScope
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.security.SecurityRequirements
import io.swagger.v3.oas.annotations.security.SecurityScheme
import io.swagger.v3.oas.annotations.security.SecuritySchemes
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@OpenAPIDefinition(
    info = Info(title = "Issuer", version = "1.0.0", description = "Verifiable Credentials Issuer API"),
    security = [SecurityRequirement(name = "bearer", scopes = ["openid"])],
)
@SecurityRequirements(SecurityRequirement(name = "bearer", scopes = ["openid"]))
@SecuritySchemes(SecurityScheme(name = "bearer", type = SecuritySchemeType.OPENIDCONNECT,
    flows = OAuthFlows(authorizationCode = OAuthFlow(
        authorizationUrl = "http://localhost:9091/oauth2/authorize",
        tokenUrl = "http://localhost:9091/oauth2/token", scopes = [OAuthScope("openid")])
    )
)
)
@SpringBootApplication
class IssuerApplication

fun main(args: Array<String>) {
    runApplication<IssuerApplication>(*args)
}
