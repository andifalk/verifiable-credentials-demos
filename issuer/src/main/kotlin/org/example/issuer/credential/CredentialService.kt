package org.example.issuer.credential

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.stereotype.Service
import java.net.URLDecoder
import java.time.Instant
import java.util.Date
import java.util.UUID

@Service
class CredentialService(
    private val rsaKey: RSAKey,
    private val objectMapper: ObjectMapper,
) {
    fun issueCredential(
        jwt: Jwt,
        request: CredentialRequest,
    ): String {
        // Dummy subject — extract from access token in production
        val subject = jwt.subject
        var credentialId: String? = null
        if (jwt.hasClaim("authorization_details")) {
            val detailsString = URLDecoder.decode(jwt.getClaim<String>("authorization_details"), "UTF-8")

            val authorizationDetails =
                objectMapper.readValue(detailsString, object : TypeReference<List<AuthorizationDetail>>() {})

            credentialId = authorizationDetails.getOrNull(0)?.credentialConfigurationId
        }

        if (credentialId == null) {
            if (request.credentialIdentifier != null) {
                credentialId = request.credentialIdentifier
            } else {
                error("Credential identifier is not set")
            }
        }

        // 1. Define the VC payload
        val now = Instant.now()
        val vcClaims =
            mapOf(
                "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                "type" to listOf("VerifiableCredential", credentialId),
                "credentialSubject" to
                    "credentialSubject" to buildCredentialSubject(credentialId, subject),
            )

        // 2. Standard JWT claims
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer("http://localhost:8080")
                .subject(subject)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(600)))
                .claim("vc", vcClaims)
                .jwtID(UUID.randomUUID().toString())
                .build()

        // 3. Sign it
        val signer = RSASSASigner(rsaKey.toRSAPrivateKey())
        val signedJWT =
            SignedJWT(
                JWSHeader
                    .Builder(JWSAlgorithm.RS256)
                    .keyID(rsaKey.keyID)
                    .type(JOSEObjectType.JWT)
                    .build(),
                claims,
            )
        signedJWT.sign(signer)

        return signedJWT.serialize()
    }

    private fun buildCredentialSubject(
        identifier: String,
        subject: String,
    ): Map<String, Any> =
        when (identifier) {
            "UniversityDegreeCredential" ->
                mapOf(
                    "id" to subject,
                    "name" to "Alice Schmidt",
                    "degree" to
                        mapOf(
                            "type" to "BachelorDegree",
                            "name" to "Bachelor of Science in Computer Science",
                            "university" to "TU Munich",
                            "awarded" to "2020-07-15",
                        ),
                )

            "DigitalIDCredential" ->
                mapOf(
                    "id" to subject,
                    "given_name" to "Alice",
                    "family_name" to "Schmidt",
                    "birthdate" to "1995-05-23",
                    "nationality" to "DE",
                    "document_type" to "national_id_card",
                )

            "BankAccountCredential" ->
                mapOf(
                    "id" to subject,
                    "account_holder" to "Alice Schmidt",
                    "iban" to "DE89370400440532013000",
                    "bic" to "COBADEFFXXX",
                    "bank" to "Commerzbank",
                    "account_type" to "checking",
                )

            else -> throw IllegalArgumentException("Unsupported credential type: $identifier")
        }
}
