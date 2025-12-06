package org.example.issuer.credential

import com.fasterxml.jackson.annotation.JsonProperty
import com.nimbusds.jose.jwk.JWK

data class CredentialRequest(
    val format: String,
    @get:JsonProperty("credential_identifier")
    val credentialIdentifier: String? = null,
    @get:JsonProperty("credential_configuration_id")
    val credentialConfigurationId: String? = null,
    val proofs: Proof? = null,
    @get:JsonProperty("credential_response_encryption")
    val credentialResponseEncryption: CredentialEncryption? = null,
)

data class CredentialEncryption(
    val jwk: JWK,
    val alg: String,
    val enc: String,
)

data class Proof(
    val jwt: String? = null,
    val attestation: List<String>? = null,
    @get:JsonProperty("di_vp")
    val diVp: String? = null,
)

data class DiVpProof(
    @get:JsonProperty("@context")
    val context: List<String>? = null,
    val type: List<String>? = null,
    val holder: String? = null,
    val proof: List<DataIntegrityProof>?,
)

data class DataIntegrityProof(
    val type: String = "VerifiablePresentation",
    val cryptoSuite: String? = null,
    val proofPurpose: String? = null,
    val verificationMethod: String? = null,
    val created: java.time.Instant? = null,
    val challenge: String? = null,
    val domain: String? = null,
    val proofValue: String? = null,
)

data class CredentialResponse(
    val credentials: List<Credential>? = null,
    @get:JsonProperty("transaction_id")
    val transactionId: String? = null,
    val interval: Int? = null,
    @get:JsonProperty("notification_id")
    val notificationId: String? = null,
)

data class Credential(
    val credential: String,
)

enum class ProofType(
    val value: String,
) {
    JWT("jwt"),
    CWT("cwt"),
    LDP_VP("ldp_vp"),
}

data class AuthorizationDetail(
    val type: String = "openid_credential",
    @get:JsonProperty("credential_configuration_id")
    val credentialConfigurationId: String? = null,
    val format: String? = null,
)
