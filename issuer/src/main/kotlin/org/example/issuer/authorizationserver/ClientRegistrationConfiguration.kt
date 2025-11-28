package org.example.issuer.authorizationserver

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import java.util.UUID

@Configuration
class ClientRegistrationConfiguration {
    @Bean
    fun registeredClientRepository(passwordEncoder: PasswordEncoder): RegisteredClientRepository {
        val client =
            RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("demo-client")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8080/credentials/DigitalIDCredential/callback")
                .redirectUri("http://localhost:8080/credentials/UniversityDegreeCredential/callback")
                .redirectUri("http://localhost:8080/credentials/DriversLicenseCredential/callback")
                .redirectUri("http://127.0.0.1:4200/callback")
                .scope("openid")
                .scope("vc_issuance")
                .clientSettings(
                    ClientSettings
                        .builder()
                        .requireProofKey(false)
                        .requireAuthorizationConsent(false)
                        .build(),
                ).build()
        return InMemoryRegisteredClientRepository(client)
    }
}
