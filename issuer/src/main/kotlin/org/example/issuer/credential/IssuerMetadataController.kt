package org.example.issuer.credential

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.net.URI

private const val BASE_URL = "http://localhost:8080"

@RestController
class IssuerMetadataController {
    @GetMapping("/.well-known/openid-credential-issuer")
    fun issuerMetadata(): ResponseEntity<IssuerMetadata> {
        val issuerMetadata =
            IssuerMetadata(
                credentialIssuer = BASE_URL,
                authorizationServers = setOf(BASE_URL),
                credentialEndpoint = URI.create("$BASE_URL/credential").toURL(),
                credentialConfigurationsSupported =
                    mapOf(
                        "UniversityDegreeCredential" to
                            CredentialConfigurationSupported(
                                format = "jwt_vc",
                            ),
                        "DigitalIDCredential" to
                            CredentialConfigurationSupported(
                                format = "jwt_vc",
                            ),
                        "BankAccountCredential" to
                            CredentialConfigurationSupported(
                                format = "jwt_vc",
                                proofTypesSupported = mapOf("jwt" to ProofTypeSupported(setOf("RSA256"))),
                            ),
                    ),
            )
        return ResponseEntity.ok(issuerMetadata)
    }
}
