package org.example.verifier

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@EnableConfigurationProperties(VerifierConfigurationProperties::class)
@SpringBootApplication
class VerifierApplication

fun main(args: Array<String>) {
    runApplication<VerifierApplication>(*args)
}
