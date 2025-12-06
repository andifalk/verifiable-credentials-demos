package org.example.issuer.authorizationserver

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.example.issuer.common.IssuerConsts.BASE_URL
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID

private const val BIT_SIZE = 3072

private const val ORDER_PUBLIC = 1

private const val ORDER_CREDENTIAL = 2

private const val ORDER_AUTHORIZATION_SERVER = 3

private const val ORDER_DEFAULT = 4

@Configuration
@EnableWebSecurity
class AuthorizationServerConfig {
    @Bean
    @Order(ORDER_PUBLIC)
    fun publicSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .securityMatcher(
                "/.well-known/openid-credential-issuer/**",
                "/.well-known/jwt-vc-issuer/**",
                "/credential_offer/**",
                "/error/**",
                "/v3/api-docs/**",
                "/swagger-ui.html",
                "/swagger-ui/**",
            ).anonymous {}
            // .csrf { csrf -> csrf.disable() }
            .authorizeHttpRequests { authorize ->
                authorize
                    .anyRequest()
                    .permitAll()
            }

        return http.build()
    }

    @Bean
    @Order(ORDER_CREDENTIAL)
    fun credentialSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .securityMatcher("/credential/**", "/deferred_credential/**")
            .csrf { csrf -> csrf.disable() }
            .authorizeHttpRequests { authorize ->
                authorize
                    .anyRequest()
                    .authenticated()
            }.oauth2ResourceServer { resourceServer -> resourceServer.jwt {} }

        return http.build()
    }

    @Bean
    @Order(ORDER_AUTHORIZATION_SERVER)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .oauth2AuthorizationServer({ authorizationServer: OAuth2AuthorizationServerConfigurer ->
                http.securityMatcher(authorizationServer.endpointsMatcher)
                authorizationServer
                    .oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0
            })
            .authorizeHttpRequests { authorize ->
                authorize
                    .anyRequest()
                    .authenticated()
            } // Redirect to the login page when not authenticated from the
            // authorization endpoint
            .exceptionHandling { exceptions: ExceptionHandlingConfigurer<HttpSecurity> ->
                exceptions
                    .defaultAuthenticationEntryPointFor(
                        LoginUrlAuthenticationEntryPoint("/login"),
                        MediaTypeRequestMatcher(MediaType.TEXT_HTML),
                    )
            }

        return http.build()
    }

    @Bean
    @Order(ORDER_DEFAULT)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorize ->
                authorize
                    .anyRequest()
                    .authenticated()
            } // Form login handles the redirect to the login page from the
            // authorization server filter chain
            .formLogin(Customizer.withDefaults())

        return http.build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

    @Bean
    fun userDetailsService(passwordEncoder: PasswordEncoder): UserDetailsService {
        val userDetails: UserDetails =
            User
                .builder()
                .username("user")
                .password(passwordEncoder.encode("secret"))
                .roles("USER")
                .build()

        return InMemoryUserDetailsManager(userDetails)
    }

    @Bean
    fun jwkSource(rsaKey: RSAKey): JWKSource<SecurityContext> {
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet(jwkSet)
    }

    @Bean
    fun generateRsaKey(): RSAKey {
        var keyPair: KeyPair
        return try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(BIT_SIZE)
            keyPair = keyPairGenerator.generateKeyPair()
            val publicKey = keyPair.public as RSAPublicKey
            val privateKey = keyPair.private as RSAPrivateKey
            RSAKey
                .Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .algorithm(JWSAlgorithm.RS256)
                .build()
        } catch (ex: NoSuchAlgorithmException) {
            error(ex)
        }
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration
            .jwtDecoder(jwkSource)

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings =
        AuthorizationServerSettings
            .builder()
            .issuer(BASE_URL)
            .build()
}
