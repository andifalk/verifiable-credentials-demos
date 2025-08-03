package org.example.issuer.authorizationserver

import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer

@Configuration
class TokenConfiguration {
    @Bean
    fun tokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> {
        val log = LoggerFactory.getLogger(AuthorizationServerConfig::class.java)
        return OAuth2TokenCustomizer { context ->
            if (context.tokenType == OAuth2TokenType.ACCESS_TOKEN) {
                val authorizationRequest =
                    context
                        .authorization
                        ?.attributes
                        ?.get("org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest")
                        as OAuth2AuthorizationRequest
                val authDetails =
                    authorizationRequest.additionalParameters?.get("authorization_details")
                if (authDetails != null) {
                    log.info("Authorization details: {}", authDetails)
                    context.claims.claim("authorization_details", authDetails)
                } else {
                    log.info("No Authorization details given")
                }
            }
        }
    }
}
