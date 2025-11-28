package org.example.wallet.controller

import org.example.wallet.credential.CredentialOffer
import org.example.wallet.credential.CredentialRequest
import org.example.wallet.credential.CredentialResponse
import org.example.wallet.credential.Credential
import org.example.wallet.credential.metadata.CredentialConfigurationSupported
import org.example.wallet.credential.metadata.IssuerMetadata
import org.example.wallet.store.IssuedCredentialStore
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.*
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.client.RestTemplate
import org.springframework.web.servlet.view.RedirectView
import org.springframework.util.LinkedMultiValueMap
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.*
import java.util.concurrent.ConcurrentHashMap

@Controller
class WalletController(
    @Value("\${issuer.base-url:http://localhost:8081}") private val issuerBaseUrl: String,
    @Value("\${issuer.auth-server.authorization-uri:http://localhost:9091/oauth2/authorize}") private val authorizationUri: String,
    @Value("\${issuer.auth-server.token-uri:http://localhost:9091/oauth2/token}") private val tokenUri: String,
    @Value("\${issuer.client.client-id:demo-client}") private val clientId: String,
    @Value("\${issuer.client.client-secret:secret}") private val clientSecret: String,
    @Value("\${issuer.client.redirect-uri:http://localhost:8080/credentials/{id}/callback}") private val redirectTemplate: String,
    private val restTemplate: RestTemplate,
    private val issuedStore: IssuedCredentialStore,
) {

    private val stateToVerifier = ConcurrentHashMap<String, String>()

    private fun fetchOffer(): CredentialOffer? {
        val url = issuerBaseUrl.trimEnd('/') + "/credential_offer"
        return try {
            restTemplate.getForObject(url, CredentialOffer::class.java)
        } catch (ex: Exception) {
            null
        }
    }

    private fun fetchIssuerMetadata(): IssuerMetadata? {
        val url = issuerBaseUrl.trimEnd('/') + "/.well-known/openid-credential-issuer"
        return try {
            restTemplate.getForObject(url, IssuerMetadata::class.java)
        } catch (ex: Exception) {
            null
        }
    }

    private fun fetchCredentialSchema(id: String): Map<String, Any>? {
        val encoded = URLEncoder.encode(id, StandardCharsets.UTF_8)
        val url = issuerBaseUrl.trimEnd('/') + "/credential_schema/" + encoded
        return try {
            restTemplate.getForObject(url, Map::class.java) as Map<String, Any>
        } catch (ex: Exception) {
            null
        }
    }

    @GetMapping("/")
    fun index(model: Model): String {
        val offer = fetchOffer()
        if (offer == null) {
            model.addAttribute("offer", null)
            model.addAttribute("error", "Unable to fetch issuer information")
        } else {
            model.addAttribute("offer", offer)
        }
        return "index"
    }

    @GetMapping("/credentials")
    fun credentials(model: Model): String {
        val offer = fetchOffer()
        model.addAttribute("offer", offer)
        return "credentials"
    }

    @GetMapping("/credentials/{id}")
    fun credentialDetail(@PathVariable id: String, model: Model): String {
        val offer = fetchOffer()
        model.addAttribute("offer", offer)
        model.addAttribute("credentialId", id)

        val metadata = fetchIssuerMetadata()
        val config: CredentialConfigurationSupported? = metadata?.credentialConfigurationsSupported?.get(id)
        model.addAttribute("configuration", config)

        val schema = fetchCredentialSchema(id)
        model.addAttribute("schema", schema)

        return "credential-detail"
    }

    @PostMapping("/credentials/{id}/request")
    fun requestCredential(
        @PathVariable id: String,
        @RequestParam(required = false, name = "redirect_uri") redirectUri: String?,
    ): RedirectView {
        // Start an authorization code flow for credential issuance.
        val state = UUID.randomUUID().toString()
        val codeVerifier = UUID.randomUUID().toString().replace("-", "")
        // For demo purposes we use 'plain' challenge; real apps should use S256
        val codeChallenge = codeVerifier
        stateToVerifier[state] = codeVerifier

        val redirect = redirectUri ?: redirectTemplate.replace("{id}", URLEncoder.encode(id, StandardCharsets.UTF_8))
        val params = mapOf(
            "response_type" to "code",
            "client_id" to clientId,
            "redirect_uri" to redirect,
            "scope" to "openid vc_issuance",
            "state" to state,
            //"code_challenge" to codeChallenge,
            //"code_challenge_method" to "plain",
            // pass raw JSON here and encode when building the query
            "authorization_details" to "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"${id}\"}]",
        )
        val query = params.map { (k, v) -> "${k}=${URLEncoder.encode(v, StandardCharsets.UTF_8)}" }.joinToString("&")
        return RedirectView(authorizationUri + "?" + query)
    }

    @GetMapping("/credentials/{id}/callback")
    fun callback(
        @PathVariable id: String,
        @RequestParam(required = false) code: String?,
        @RequestParam(required = false) state: String?,
        model: Model,
    ): String {
        model.addAttribute("credentialId", id)
        if (code == null || state == null) {
            model.addAttribute("error", "Missing code or state")
            return "credential-result"
        }
        val verifier = stateToVerifier.remove(state)
        if (verifier == null) {
            model.addAttribute("error", "Unknown state")
            return "credential-result"
        }

        // Exchange code for token
        val body = LinkedMultiValueMap<String, String>()
        body.add("grant_type", "authorization_code")
        body.add("code", code)
        body.add("redirect_uri", redirectTemplate.replace("{id}", id))
        body.add("client_id", clientId)
        body.add("client_secret", clientSecret)
        //body.add("code_verifier", verifier)

        val headers = HttpHeaders()
        headers.contentType = MediaType.APPLICATION_FORM_URLENCODED

        val tokenResp = try {
            restTemplate.postForEntity(tokenUri, HttpEntity(body, headers), Map::class.java)
        } catch (ex: Exception) {
            model.addAttribute("error", "Token exchange failed: ${ex.message}")
            return "credential-result"
        }

        val accessToken = (tokenResp.body?.get("access_token") as? String)
        if (accessToken.isNullOrBlank()) {
            model.addAttribute("error", "No access token returned")
            return "credential-result"
        }

        // Call issuer /credential endpoint with access token
        val req = CredentialRequest(credentialConfigurationId = id)
        val credHeaders = HttpHeaders()
        credHeaders.contentType = MediaType.APPLICATION_JSON
        credHeaders.setBearerAuth(accessToken)
        val resp = try {
            restTemplate.postForEntity(issuerBaseUrl.trimEnd('/') + "/credential", HttpEntity(req, credHeaders), CredentialResponse::class.java)
        } catch (ex: Exception) {
            model.addAttribute("error", "Credential request failed: ${ex.message}")
            return "credential-result"
        }

        val credential = resp.body?.credentials?.firstOrNull()?.credential
        if (credential != null) {
            issuedStore.add(credential)
        }
        model.addAttribute("issuedCredential", credential)
        return "credential-result"
    }

    @GetMapping("/my-credentials")
    fun myCredentials(model: Model): String {
        val list = issuedStore.getAll()
        model.addAttribute("credentials", list)
        return "my-credentials"
    }
}
