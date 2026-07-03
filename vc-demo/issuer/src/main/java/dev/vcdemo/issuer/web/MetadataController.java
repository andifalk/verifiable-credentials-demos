package dev.vcdemo.issuer.web;

import dev.vcdemo.issuer.model.CredentialType;
import dev.vcdemo.issuer.service.IssuerKeyService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class MetadataController {

    private final String issuer;
    private final IssuerKeyService keys;

    public MetadataController(@Value("${issuer.base-url}") String issuer, IssuerKeyService keys) {
        this.issuer = issuer;
        this.keys = keys;
    }

    @GetMapping("/.well-known/openid-credential-issuer")
    Map<String, Object> credentialIssuerMetadata() {
        Map<String, Object> configurations = java.util.Arrays.stream(CredentialType.values())
                .collect(Collectors.toMap(CredentialType::configurationId, this::configurationMetadata,
                        (left, right) -> left, LinkedHashMap::new));
        return Map.of(
                "credential_issuer", issuer,
                "authorization_servers", List.of(issuer),
                "credential_endpoint", issuer + "/credential",
                "nonce_endpoint", issuer + "/nonce",
                "credential_configurations_supported", configurations);
    }

    @GetMapping("/.well-known/oauth-authorization-server")
    Map<String, Object> authorizationServerMetadata() {
        return Map.of(
                "issuer", issuer,
                "token_endpoint", issuer + "/oauth2/token",
                "grant_types_supported", List.of("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                "token_endpoint_auth_methods_supported", List.of("none"));
    }

    @GetMapping("/jwks")
    Map<String, Object> jwks() {
        return keys.publicJwkSet();
    }

    @GetMapping("/.well-known/jwt-vc-issuer")
    Map<String, Object> jwtVcIssuerMetadata() {
        return Map.of("issuer", issuer, "jwks_uri", issuer + "/jwks");
    }

    @GetMapping("/credentials/types/{configurationId}")
    Map<String, Object> typeMetadata(@PathVariable String configurationId) {
        CredentialType type = CredentialType.fromConfigurationId(configurationId);
        List<Map<String, Object>> claims = type.claims().stream()
                .map(name -> Map.<String, Object>of(
                        "path", List.of(name),
                        "display", List.of(Map.of("locale", "en-US", "name", humanize(name))),
                        "sd", "always"))
                .toList();
        return Map.of(
                "vct", issuer + "/credentials/types/" + type.configurationId(),
                "name", type.displayName(),
                "description", "Demo " + type.displayName() + " encoded as an SD-JWT VC",
                "display", List.of(Map.of(
                        "locale", "en-US",
                        "name", type.displayName(),
                        "rendering", Map.of("simple", Map.of(
                                "background_color", color(type),
                                "text_color", "#ffffff")))),
                "claims", claims);
    }

    private Map<String, Object> configurationMetadata(CredentialType type) {
        return Map.of(
                "format", "dc+sd-jwt",
                "scope", type.configurationId(),
                "vct", issuer + "/credentials/types/" + type.configurationId(),
                "cryptographic_binding_methods_supported", List.of("jwk"),
                "credential_signing_alg_values_supported", List.of("ES256"),
                "proof_types_supported", Map.of("jwt", Map.of(
                        "proof_signing_alg_values_supported", List.of("ES256"))),
                "display", List.of(Map.of("name", type.displayName(), "locale", "en-US")));
    }

    private String humanize(String value) {
        String words = value.replace('_', ' ');
        return Character.toUpperCase(words.charAt(0)) + words.substring(1);
    }

    private String color(CredentialType type) {
        return switch (type) {
            case PERSONAL_ID -> "#185FA5";
            case UNIVERSITY_DIPLOMA -> "#534AB7";
            case DRIVERS_LICENSE -> "#0F6E56";
        };
    }
}
