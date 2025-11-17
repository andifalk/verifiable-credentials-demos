package org.example.issuer.credential.metadata

import org.example.issuer.common.IssuerConsts
import org.example.issuer.common.IssuerConsts.BASE_URL
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.net.URI

@RestController
class IssuerMetadataController {

    @GetMapping("/.well-known/jwt-vc-issuer")
    fun jwtVcIssuer(): ResponseEntity<JwtVcIssuerMetadata> {
        val issuerMetadata = JwtVcIssuerMetadata(
            issuer = BASE_URL,
            jwksUri = "$BASE_URL/oauth2/jwks"
        )
        return ResponseEntity.ok(issuerMetadata)
    }

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
                                proofTypesSupported =
                                    mapOf(
                                        "jwt" to
                                            ProofTypeSupported(
                                                setOf("RSA256"),
                                            ),
                                    ),
                            ),
                    ),
            )
        return ResponseEntity.ok(issuerMetadata)
    }
}
