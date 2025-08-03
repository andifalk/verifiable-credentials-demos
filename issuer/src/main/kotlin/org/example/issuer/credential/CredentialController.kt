package org.example.issuer.credential

import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

private const val BASE_URL = "http://localhost:8080"

@RestController
@RequestMapping("/credential")
class CredentialController(
    private val credentialService: CredentialService,
) {
    @PostMapping
    fun issuerCredential(
        @AuthenticationPrincipal jwt: Jwt,
        @RequestBody credentialRequest: CredentialRequest,
    ): ResponseEntity<CredentialResponse> {
        val credential = credentialService.issueCredential(jwt, credentialRequest)
        val response = CredentialResponse(credential)
        return ResponseEntity.ok(response)
    }
}
