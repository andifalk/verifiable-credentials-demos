package org.example.issuer.credential.offer

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

private const val BASE_URL = "http://localhost:8080"

@RestController
@RequestMapping("/credential_offer")
class CredentialOfferController {
    @GetMapping
    fun getCredentialOffer(): ResponseEntity<CredentialOffer> {
        val response =
            CredentialOffer(
                credentialIssuer = BASE_URL,
                credentialConfigurationIds =
                    listOf(
                        "UniversityDegreeCredential",
                        "DigitalIDCredential",
                        "BankAccountCredential",
                    ),
                grants = Grants(authorizationCode = GrantAuthorizationCode(UUID.randomUUID().toString())),
            )
        return ResponseEntity.ok(response)
    }
}
