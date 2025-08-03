package org.example.issuer.credential.offer

import com.fasterxml.jackson.annotation.JsonProperty

data class CredentialOffer(
    @JsonProperty("credential_issuer")
    val credentialIssuer: String,
    @JsonProperty("credential_configuration_ids")
    val credentialConfigurationIds: List<String>,
    val grants: Grants,
)

data class Grants(
    @JsonProperty("authorization_code")
    val authorizationCode: GrantAuthorizationCode? = null,
    @JsonProperty("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    val preAuthorizedCode: PreAuthorizedCode? = null,
)

data class GrantAuthorizationCode(
    @JsonProperty("issuer_state")
    val issuerState: String,
)

data class PreAuthorizedCode(
    @JsonProperty("pre-authorized_code")
    val preAuthorizedCode: String,
    @JsonProperty("tx_code")
    val txCode: TxCode? = null,
)

data class TxCode(
    @JsonProperty("input_mode")
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
