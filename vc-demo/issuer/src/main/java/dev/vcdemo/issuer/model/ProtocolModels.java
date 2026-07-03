package dev.vcdemo.issuer.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

import java.util.List;
import java.util.Map;

public final class ProtocolModels {

    private ProtocolModels() {
    }

    public record CreateOfferRequest(Map<String, Object> claims) {
    }

    public record OfferCreated(String offer_uri, String pre_authorized_code, Map<String, Object> credential_offer) {
    }

    public record Proofs(List<String> jwt) {
    }

    public record CredentialRequest(
            @JsonProperty("credential_configuration_id") @NotBlank String credentialConfigurationId,
            Proofs proofs) {
    }

    public record IssuedCredential(String credential) {
    }

    public record CredentialResponse(List<IssuedCredential> credentials) {
    }

    public record ErrorResponse(String error, @JsonProperty("error_description") String description) {
    }
}
