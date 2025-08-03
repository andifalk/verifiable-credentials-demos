package org.example.issuer.credential

import com.fasterxml.jackson.annotation.JsonProperty
import com.nimbusds.jose.jwk.JWK

data class CredentialRequest(
    val format: String,
    @JsonProperty("credential_identifier")
    val credentialIdentifier: String? = null,
    val proof: Proof? = null,
    @JsonProperty("credential_response_encryption")
    val credentialResponseEncryption: CredentialEncryption? = null,
)

data class CredentialEncryption(
    val jwk: JWK,
    val alg: String,
    val enc: String,
)

data class Proof(
    @JsonProperty("proof_type")
    val proofType: ProofType,
    val jwt: String? = null,
    val cwt: String? = null,
    @JsonProperty("ldp_vp")
    val ldpVp: String? = null,
)

data class CredentialResponse(
    val credential: String? = null,
    @JsonProperty("transaction_id")
    val transactionId: String? = null,
    @JsonProperty("c_nonce")
    val cNonce: String? = null,
    @JsonProperty("c_nonce_expires_in")
    val cNonceExpiresIn: Long? = null,
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
    @JsonProperty("credential_configuration_id")
    val credentialConfigurationId: String? = null,
    val format: String? = null,
)
