package org.example.wallet.credential.metadata

import com.fasterxml.jackson.annotation.JsonProperty
import java.net.URI

data class IssuerMetadata(
    @get:JsonProperty("credential_issuer")
    val credentialIssuer: String? = null,
    @get:JsonProperty("credential_configurations_supported")
    val credentialConfigurationsSupported: Map<String, CredentialConfigurationSupported>? = null,
)

data class CredentialConfigurationSupported(
    val format: String? = null,
    val scope: String? = null,
    val display: CredentialDisplay? = null,
)

data class CredentialDisplay(
    val name: String? = null,
    val locale: String? = null,
    val logo: Logo? = null,
    val description: String? = null,
    @get:JsonProperty("background_color")
    val backgroundColor: String? = null,
    @get:JsonProperty("text_color")
    val textColor: String? = null,
)

data class Logo(
    val uri: URI? = null,
    @get:JsonProperty("alt_text")
    val altText: String? = null,
)

