package org.example.wallet.credential

import com.fasterxml.jackson.annotation.JsonProperty

data class CredentialRequest(
    val format: String = "jwt_vc",
    @get:JsonProperty("credential_identifier")
    val credentialIdentifier: String? = null,
    @get:JsonProperty("credential_configuration_id")
    val credentialConfigurationId: String? = null,
    val proofs: Any? = null,
)

data class CredentialResponse(
    val credentials: List<Credential>? = null
)

data class Credential(
    val credential: String
)

