package org.example.wallet

import org.example.wallet.controller.WalletController
import org.example.wallet.credential.CredentialOffer
import org.example.wallet.credential.metadata.CredentialConfigurationSupported
import org.example.wallet.credential.metadata.CredentialDisplay
import org.example.wallet.credential.metadata.IssuerMetadata
import org.example.wallet.store.IssuedCredentialStore
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.springframework.ui.ConcurrentModel
import org.springframework.web.client.RestTemplate
import java.net.URI

class WalletControllerMetadataTest {

    @Test
    fun `credentialDetail attaches configuration when metadata present`() {
        val offer = CredentialOffer(credentialIssuer = "http://issuer.example", credentialConfigurationIds = listOf("TestCredential"))
        val restTemplate = Mockito.mock(RestTemplate::class.java)
        // mock credential_offer
        Mockito.`when`(restTemplate.getForObject("http://localhost:8081/credential_offer", CredentialOffer::class.java))
            .thenReturn(offer)
        // mock metadata
        val config = CredentialConfigurationSupported(format = "jwt_vc", display = CredentialDisplay(name = "Test Credential", locale = "en", logo = null, description = "A test credential", backgroundColor = null, textColor = null))
        val metadata = IssuerMetadata(credentialIssuer = "http://issuer.example", credentialConfigurationsSupported = mapOf("TestCredential" to config))
        Mockito.`when`(restTemplate.getForObject("http://localhost:8081/.well-known/openid-credential-issuer", IssuerMetadata::class.java))
            .thenReturn(metadata)

        val controller = WalletController(
            "http://localhost:8081",
            "http://localhost:9091/oauth2/authorize",
            "http://localhost:9091/oauth2/token",
            "demo-client",
            "secret",
            "http://localhost:8080/credentials/{id}/callback",
            restTemplate,
            IssuedCredentialStore(),
        )
        val model = ConcurrentModel()
        val view = controller.credentialDetail("TestCredential", model)

        assertEquals("credential-detail", view)
        val configuration = model.getAttribute("configuration") as CredentialConfigurationSupported?
        assertNotNull(configuration)
        assertEquals("jwt_vc", configuration?.format)
        assertEquals("Test Credential", configuration?.display?.name)
    }
}
