package org.example.sd.model

import com.fasterxml.jackson.annotation.JsonProperty

data class IdentityCredential(
    val sub: String,
    @param:JsonProperty("given_name")
    val givenName: String,
    @param:JsonProperty("family_name")
    val familyName: String,
    @param:JsonProperty("birth_date")
    val birthdate: String,
    @param:JsonProperty("is_over_18")
    val isOver18: Boolean,
    val nationality: Nationality,
    val address: Address,
    @param:JsonProperty("document_type")
    val documentType: DocumentType,
)

data class Address(
    @param:JsonProperty("street_address")
    val street: String,
    val city: String,
    @param:JsonProperty("postal_code")
    val postalCode: String,
    val country: Country,
)

enum class Nationality(
    private val countryCode: String,
) {
    US("US"),
    CA("CA"),
    GB("GB"),
    FR("FR"),
    DE("DE"),
    IN("IN"),
    CN("CN"),
    JP("JP"),
    AU("AU"),
    BR("BR"),
}

enum class Country(
    private val countryCode: String,
) {
    US("US"),
    CA("CA"),
    GB("GB"),
    FR("FR"),
    DE("DE"),
    IN("IN"),
    CN("CN"),
    JP("JP"),
    AU("AU"),
    BR("BR"),
}

enum class DocumentType(
    private val type: String,
) {
    PASSPORT("passport"),
    NATIONAL_ID_CARD("national_id_card"),
    DRIVER_LICENSE("driver_license"),
}
