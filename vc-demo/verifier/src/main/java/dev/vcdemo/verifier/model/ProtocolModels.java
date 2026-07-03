package dev.vcdemo.verifier.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

public final class ProtocolModels {

    private ProtocolModels() {
    }

    public record CreatedPresentationRequest(
            @JsonProperty("transaction_id") String transactionId,
            @JsonProperty("authorization_request_uri") String authorizationRequestUri,
            @JsonProperty("expires_in") long expiresIn) {
    }

    public record PresentationResult(
            @JsonProperty("transaction_id") String transactionId,
            String status,
            @JsonProperty("credential_type") String credentialType,
            String issuer,
            Map<String, Object> claims,
            String error) {
    }

    public record DirectPostResponse(@JsonProperty("redirect_uri") String redirectUri) {
    }

    public record ErrorResponse(String error, @JsonProperty("error_description") String description) {
    }
}
