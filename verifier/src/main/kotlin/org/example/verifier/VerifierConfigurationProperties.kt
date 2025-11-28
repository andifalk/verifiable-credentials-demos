package org.example.verifier

import org.springframework.boot.context.properties.ConfigurationProperties
import java.net.URI

@ConfigurationProperties(prefix = "verifier")
data class VerifierConfigurationProperties(val walletUrl: URI) {
}
