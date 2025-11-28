package org.example.verifier.verification

import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController

@RestController("/verification")
class VerificationController {

    @PostMapping("/cb")
    fun callback() {
        // Handle verification callback
    }
}