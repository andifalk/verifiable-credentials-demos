package org.example.verifier

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class VerifierApplication

fun main(args: Array<String>) {
    runApplication<VerifierApplication>(*args)
}
