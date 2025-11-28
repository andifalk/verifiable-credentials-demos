package org.example.issuer.credential

import org.example.issuer.common.IssuerConsts.BASE_URL
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/credential_schema")
class SchemaController {
    @GetMapping("/{id}")
    fun getSchema(@PathVariable id: String): ResponseEntity<Map<String, Any>> {
        val schema = when (id) {
            "UniversityDegreeCredential" -> mapOf(
                "title" to "University Degree Credential",
                "type" to "object",
                "properties" to mapOf(
                    "id" to mapOf("type" to "string"),
                    "name" to mapOf("type" to "string"),
                    "degree" to mapOf("type" to "object", "properties" to mapOf("type" to mapOf("type" to "string"), "name" to mapOf("type" to "string")))
                )
            )
            "DigitalIDCredential" -> mapOf(
                "title" to "Digital ID",
                "type" to "object",
                "properties" to mapOf(
                    "id" to mapOf("type" to "string"),
                    "given_name" to mapOf("type" to "string"),
                    "family_name" to mapOf("type" to "string"),
                    "birthdate" to mapOf("type" to "string", "format" to "date")
                )
            )
            "DriversLicenseCredential" -> mapOf(
                "title" to "Driver's License",
                "type" to "object",
                "properties" to mapOf(
                    "id" to mapOf("type" to "string"),
                    "issued_at" to mapOf("type" to "string", "format" to "date")
                )
            )
            else -> mapOf("title" to id, "type" to "object")
        }
        return ResponseEntity.ok(schema)
    }
}

