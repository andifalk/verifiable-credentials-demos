package org.example.wallet

import org.example.wallet.controller.WalletController
import org.example.wallet.credential.CredentialResponse
import org.example.wallet.credential.Credential
import org.example.wallet.store.IssuedCredentialStore
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.springframework.ui.ConcurrentModel
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.RestTemplate
import org.springframework.http.*

class WalletControllerCallbackTest {

    @Test
    fun `callback exchanges code and requests credential`() {
        val restTemplate = Mockito.mock(RestTemplate::class.java)
        val tokenRespMap = mapOf("access_token" to "dummy-token")
        Mockito.`when`(restTemplate.postForEntity(Mockito.eq("http://localhost:9091/oauth2/token"), Mockito.any(HttpEntity::class.java), Mockito.eq(Map::class.java)))
            .thenReturn(ResponseEntity.ok(tokenRespMap))

        val credResp = CredentialResponse(listOf(Credential("issued-jwt")))
        Mockito.`when`(restTemplate.postForEntity(Mockito.eq("http://localhost:8081/credential"), Mockito.any(HttpEntity::class.java), Mockito.eq(CredentialResponse::class.java)))
            .thenReturn(ResponseEntity.ok(credResp))

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
        // simulate state stored in controller's map by invoking requestCredential first to populate state
        val redirect = controller.requestCredential("TestCredential", null)
        val url = redirect.url!!
        val state = Regex("state=([0-9a-fA-F\\-]+)").find(url)!!.groupValues[1]

        val model = ConcurrentModel()
        val view = controller.callback("TestCredential", "dummy-code", state, model)

        assertEquals("credential-result", view)
        assertNull(model.getAttribute("error"))
        assertEquals("issued-jwt", model.getAttribute("issuedCredential"))
    }
}
