package org.example.wallet

import org.example.wallet.controller.WalletController
import org.example.wallet.credential.CredentialOffer
import org.example.wallet.store.IssuedCredentialStore
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.springframework.ui.ConcurrentModel
import org.springframework.web.client.RestTemplate

class WalletControllerTest {

    @Test
    fun `index returns offer when resttemplate succeeds`() {
        val offer = CredentialOffer(credentialIssuer = "http://issuer.example", credentialConfigurationIds = listOf("cred-1", "cred-2"))
        val restTemplate = Mockito.mock(RestTemplate::class.java)
        Mockito.`when`(restTemplate.getForObject("http://localhost:8081/credential_offer", CredentialOffer::class.java))
            .thenReturn(offer)

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
        val view = controller.index(model)

        assertEquals("index", view)
        val modelOffer = model.getAttribute("offer") as CredentialOffer?
        assertNotNull(modelOffer)
        assertEquals("http://issuer.example", modelOffer?.credentialIssuer)
    }

    @Test
    fun `index sets error when resttemplate returns null`() {
        val restTemplate = Mockito.mock(RestTemplate::class.java)
        Mockito.`when`(restTemplate.getForObject("http://localhost:8081/credential_offer", CredentialOffer::class.java))
            .thenReturn(null)

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
        val view = controller.index(model)

        assertEquals("index", view)
        assertNull(model.getAttribute("offer"))
        assertNotNull(model.getAttribute("error"))
    }
}
