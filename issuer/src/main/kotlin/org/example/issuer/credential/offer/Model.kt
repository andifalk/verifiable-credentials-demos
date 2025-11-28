package org.example.issuer.credential.offer

import com.fasterxml.jackson.annotation.JsonProperty

data class CredentialOffer(
    @param:JsonProperty("credential_issuer")
    val credentialIssuer: String,
    @param:JsonProperty("credential_configuration_ids")
    val credentialConfigurationIds: List<String>,
    val grants: Grants,
)

data class Grants(
    @param:JsonProperty("authorization_code")
    val authorizationCode: GrantAuthorizationCode? = null,
    @param:JsonProperty("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    val preAuthorizedCode: PreAuthorizedCode? = null,
)

data class GrantAuthorizationCode(
    @param:JsonProperty("issuer_state")
    val issuerState: String,
)

data class PreAuthorizedCode(
    @param:JsonProperty("pre-authorized_code")
    val preAuthorizedCode: String,
    @param:JsonProperty("tx_code")
    val txCode: TxCode? = null,
)

data class TxCode(
    @param:JsonProperty("input_mode")
    val inputMode: InputMode,
    val length: Int? = null,
    val description: String? = null,
)

enum class InputMode(
    val value: String,
) {
    NUMERIC("numeric"),
    TEXT("text"),
}
