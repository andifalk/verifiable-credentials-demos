package org.example.wallet.credential

import com.fasterxml.jackson.annotation.JsonProperty

data class CredentialOffer(
    @param:JsonProperty("credential_issuer")
    val credentialIssuer: String? = null,
    @param:JsonProperty("credential_configuration_ids")
    val credentialConfigurationIds: List<String>? = emptyList()
)

