package org.example.verifier.authorization

import com.fasterxml.jackson.annotation.JsonProperty

data class AuthorizationRequest(
    val iss: String,
    val aud: String,
    @param:JsonProperty("response_type")
    val responseType: String,
    @param:JsonProperty("response_mode")
    val responseMode: String?,
    @param:JsonProperty("client_id")
    val clientId: String,
    @param:JsonProperty("redirect_uri")
    val redirectUri: String?,
    @param:JsonProperty("response_uri")
    val responseUri: String?,
    val scope: String?,
    val state: String,
    @param:JsonProperty("dcql_query")
    val dcqlQuery: DcqlQuery,
    val nonce: String?,
)

data class DcqlQuery(
    val credentials: List<Credential>,
)

data class Credential(
    val id: String,
    val format: String,
    val multiple: Boolean,
    val meta: MutableMap<String, Any> = mutableMapOf(),
    val claims: MutableList<Claim> = mutableListOf(),
)

data class Claim(
    val path: MutableList<String> = mutableListOf(),
)

enum class ResponseMode(val mode: String) {
    QUERY("query"),
    FRAGMENT("fragment"),
    FORM_POST("form_post"),
    DIRECT_POST("direct_post")
}

enum class ResponseType(val type: String) {
    CODE("code"),
    TOKEN("token"),
    ID_TOKEN("id_token"),
    VP_TOKEN("vp_token")
}