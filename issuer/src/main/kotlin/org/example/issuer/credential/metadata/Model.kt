package org.example.issuer.credential.metadata

import com.fasterxml.jackson.annotation.JsonProperty
import java.net.URI
import java.net.URL

data class IssuerMetadata(
    @get:JsonProperty("credential_issuer")
    val credentialIssuer: String,
    @get:JsonProperty("authorization_servers")
    val authorizationServers: Set<String>? = null,
    @get:JsonProperty("credential_endpoint")
    val credentialEndpoint: URL? = null,
    @get:JsonProperty("batch_credential_endpoint")
    val batchCredentialEndpoint: URL? = null,
    @get:JsonProperty("deferred_credential_endpoint")
    val deferredCredentialEndpoint: URL? = null,
    @get:JsonProperty("notification_endpoint")
    val notificationEndpoint: URL? = null,
    @get:JsonProperty("credential_response_encryption")
    val credentialResponseEncryption: CredentialResponseEncryption? = null,
    @get:JsonProperty("credential_identifiers_supported")
    val credentialIdentifiersSupported: Boolean? = null,
    @get:JsonProperty("credential_configurations_supported")
    val credentialConfigurationsSupported: Map<String, CredentialConfigurationSupported>,
    @get:JsonProperty("signed_metadata")
    val signedMetadata: String? = null,
    val display: Display? = null,
)

data class JwtVcIssuerMetadata(
    val issuer: String,
    val jwksUri: String? = null,
    val jwks: JwksKeys? = null,
)

data class JwksKeys(
    val keys: List<JwksKey>? = null,
)

data class JwksKey(
    val kid: String,
    val kty: String,
    val crv: String,
    val x: String,
    val y: String,
)

data class CredentialConfigurationSupported(
    val format: String,
    val scope: String? = null,
    @param:JsonProperty("cryptographic_binding_methods_supported")
    val cryptographicBindingMethodsSupported: Set<String>? = null,
    @param:JsonProperty("cryptographic_signing_alg_values_supported")
    val credentialSigningAlgValuesSupported: Set<String>? = null,
    @param:JsonProperty("proof_types_supported")
    val proofTypesSupported: Map<String, ProofTypeSupported>? = null,
    val display: CredentialDisplay? = null,
)

data class CredentialResponseEncryption(
    @param:JsonProperty("alg_values_supported")
    val algValuesSupported: Set<String>,
    @param:JsonProperty("enc_values_supported")
    val encValuesSupported: Set<String>,
    @param:JsonProperty("encryption_required")
    val encryptionRequired: Boolean,
)

data class ProofTypeSupported(
    @param:JsonProperty("proof_signing_alg_values_supported:")
    val proofSigningAlgValuesSupported: Set<String>,
)

data class Display(
    val name: String,
    val locale: String?,
    val logo: Logo?,
    val description: String?,
    @param:JsonProperty("background_color")
    val backgroundColor: String?,
    @param:JsonProperty("text_color")
    val textColor: String?,
    @param:JsonProperty("background_image")
    val backgroundImage: BackgroundImage?,
)

data class CredentialDisplay(
    val name: String,
    val locale: String?,
    val logo: Logo?,
    val description: String?,
    @param:JsonProperty("background_color")
    val backgroundColor: String?,
    @param:JsonProperty("text_color")
    val textColor: String?,
    @param:JsonProperty("background_image")
    val backgroundImage: BackgroundImage?,
)

data class BackgroundImage(
    val uri: URI,
)

data class Logo(
    val uri: URI,
    @param:JsonProperty("alt_text")
    val altText: String?,
)
