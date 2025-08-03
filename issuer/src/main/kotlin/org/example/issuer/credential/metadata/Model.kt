package org.example.issuer.credential.metadata

import com.fasterxml.jackson.annotation.JsonProperty
import java.net.URI
import java.net.URL

data class IssuerMetadata(
    @JsonProperty("credential_issuer")
    val credentialIssuer: String,
    @JsonProperty("authorization_servers")
    val authorizationServers: Set<String>? = null,
    @JsonProperty("credential_endpoint")
    val credentialEndpoint: URL? = null,
    @JsonProperty("batch_credential_endpoint")
    val batchCredentialEndpoint: URL? = null,
    @JsonProperty("deferred_credential_endpoint")
    val deferredCredentialEndpoint: URL? = null,
    @JsonProperty("notification_endpoint")
    val notificationEndpoint: URL? = null,
    @JsonProperty("credential_response_encryption")
    val credentialResponseEncryption: CredentialResponseEncryption? = null,
    @JsonProperty("credential_identifiers_supported")
    val credentialIdentifiersSupported: Boolean? = null,
    @JsonProperty("credential_configurations_supported")
    val credentialConfigurationsSupported: Map<String, CredentialConfigurationSupported>,
    @JsonProperty("signed_metadata")
    val signedMetadata: String? = null,
    val display: Display? = null,
)

data class CredentialConfigurationSupported(
    val format: String,
    val scope: String? = null,
    @JsonProperty("cryptographic_binding_methods_supported")
    val cryptographicBindingMethodsSupported: Set<String>? = null,
    @JsonProperty("cryptographic_signing_alg_values_supported")
    val credentialSigningAlgValuesSupported: Set<String>? = null,
    @JsonProperty("proof_types_supported")
    val proofTypesSupported: Map<String, ProofTypeSupported>? = null,
    val display: CredentialDisplay? = null,
)

data class CredentialResponseEncryption(
    @JsonProperty("alg_values_supported")
    val algValuesSupported: Set<String>,
    @JsonProperty("enc_values_supported")
    val encValuesSupported: Set<String>,
    @JsonProperty("encryption_required")
    val encryptionRequired: Boolean,
)

data class ProofTypeSupported(
    @JsonProperty("proof_signing_alg_values_supported:")
    val proofSigningAlgValuesSupported: Set<String>,
)

data class Display(
    val name: String,
    val locale: String?,
    val logo: Logo?,
    val description: String?,
    @JsonProperty("background_color")
    val backgroundColor: String?,
    @JsonProperty("text_color")
    val textColor: String?,
    @JsonProperty("background_image")
    val backgroundImage: BackgroundImage?,
)

data class CredentialDisplay(
    val name: String,
    val locale: String?,
    val logo: Logo?,
    val description: String?,
    @JsonProperty("background_color")
    val backgroundColor: String?,
    @JsonProperty("text_color")
    val textColor: String?,
    @JsonProperty("background_image")
    val backgroundImage: BackgroundImage?,
)

data class BackgroundImage(
    val uri: URI,
)

data class Logo(
    val uri: URI,
    @JsonProperty("alt_text")
    val altText: String?,
)
