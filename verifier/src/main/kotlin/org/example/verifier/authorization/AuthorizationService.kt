package org.example.verifier.authorization

import jakarta.annotation.PostConstruct
import org.example.verifier.VerifierConfigurationProperties
import org.springframework.stereotype.Service
import org.springframework.web.client.ResponseErrorHandler
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestTemplate
import tools.jackson.databind.json.JsonMapper
import java.util.Base64

@Service
class AuthorizationService(private val verifierProperties: VerifierConfigurationProperties, private val jsonMapper: JsonMapper) {
    private lateinit var restClient: RestClient

    @PostConstruct
    fun init(){
        restClient = RestClient.builder().baseUrl(verifierProperties.walletUrl).build()
    }

    fun sendAuthorizationRequest(request: AuthorizationRequest) {
        val responseSpec = restClient.get()
            .uri("/authorize")
            .attribute("client_id", "example-client-id")
            .attribute("request", Base64.getUrlEncoder().encodeToString(jsonMapper.writeValueAsBytes(request)))
            .retrieve()
        responseSpec.onStatus { status -> status.statusCode.is4xxClientError || status.statusCode.is5xxServerError }
    }
}