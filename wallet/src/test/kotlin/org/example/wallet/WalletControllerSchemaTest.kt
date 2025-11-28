package org.example.wallet

import org.example.wallet.controller.WalletController
import org.example.wallet.credential.CredentialOffer
import org.example.wallet.store.IssuedCredentialStore
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.springframework.ui.ConcurrentModel
import org.springframework.web.client.RestTemplate
import org.springframework.web.servlet.view.RedirectView

class WalletControllerSchemaTest {

    @Test
    fun `credentialDetail attaches schema when present`() {
        val offer = CredentialOffer(credentialIssuer = "http://issuer.example", credentialConfigurationIds = listOf("TestCredential"))
        val restTemplate = Mockito.mock(RestTemplate::class.java)
        Mockito.`when`(restTemplate.getForObject("http://localhost:8081/credential_offer", CredentialOffer::class.java)).thenReturn(offer)
        val schema = mapOf("title" to "Test Credential", "type" to "object")
        Mockito.`when`(restTemplate.getForObject("http://localhost:8081/credential_schema/TestCredential", Map::class.java)).thenReturn(schema)

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
        val modelSchema = model.getAttribute("schema") as Map<*, *>?
        assertNotNull(modelSchema)
        assertEquals("Test Credential", modelSchema?.get("title"))
    }

    @Test
    fun `requestCredential returns redirect to issuer with authorization details`() {
        val restTemplate = Mockito.mock(RestTemplate::class.java)
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
        val redirect = controller.requestCredential("TestCredential", null)
        assertTrue(redirect is RedirectView)
        val url = redirect.url
        assertNotNull(url)
        assertTrue(url!!.contains("authorization_details"))
        assertTrue(url.contains("credential_configuration_id%22%3A%22TestCredential")) // encoded JSON fragment
    }
}
