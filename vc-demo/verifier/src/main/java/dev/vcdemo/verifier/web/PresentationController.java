package dev.vcdemo.verifier.web;

import dev.vcdemo.verifier.model.CredentialProfile;
import dev.vcdemo.verifier.model.ProtocolModels.CreatedPresentationRequest;
import dev.vcdemo.verifier.model.ProtocolModels.DirectPostResponse;
import dev.vcdemo.verifier.model.ProtocolModels.PresentationResult;
import dev.vcdemo.verifier.service.PresentationStore;
import dev.vcdemo.verifier.service.PresentationStore.Transaction;
import dev.vcdemo.verifier.service.SdJwtPresentationVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
public class PresentationController {

    private static final Logger log = LoggerFactory.getLogger(PresentationController.class);

    private final PresentationStore store;
    private final SdJwtPresentationVerifier presentationVerifier;
    private final ObjectMapper objectMapper;
    private final String verifierBaseUrl;
    private final String issuerUrl;
    private final String clientId;
    private final String responseUri;

    public PresentationController(PresentationStore store, SdJwtPresentationVerifier presentationVerifier,
            ObjectMapper objectMapper,
            @Value("${verifier.base-url}") String verifierBaseUrl,
            @Value("${verifier.issuer-url}") String issuerUrl) {
        this.store = store;
        this.presentationVerifier = presentationVerifier;
        this.objectMapper = objectMapper;
        this.verifierBaseUrl = verifierBaseUrl;
        this.issuerUrl = issuerUrl;
        this.responseUri = verifierBaseUrl + "/oid4vp/response";
        this.clientId = "redirect_uri:" + responseUri;
    }

    @PostMapping("/api/presentations/{credentialType}")
    CreatedPresentationRequest create(@PathVariable String credentialType) {
        log.info("OID4VP presentation creation request profile={}", credentialType);
        Transaction transaction = store.create(CredentialProfile.fromId(credentialType));
        Map<String, Object> authorizationRequest = authorizationRequest(transaction);
        String requestUri = authorizationRequestUri(authorizationRequest);
        CreatedPresentationRequest response = new CreatedPresentationRequest(transaction.id(), requestUri, 300);
        log.info("OID4VP presentation creation response transaction_id={} profile={} credential_type={} request_uri_len={}",
                transaction.id(), transaction.profile().id(), transaction.profile().credentialTypeId(),
                requestUri.length());
        return response;
    }

    @GetMapping("/api/presentations/{transactionId}/request")
    Map<String, Object> request(@PathVariable String transactionId) {
        Transaction transaction = store.find(transactionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown or expired presentation transaction"));
        Map<String, Object> response = authorizationRequest(transaction);
        log.info("OID4VP authorization request response transaction_id={} state={} nonce={} dcql_query={}",
                transaction.id(), preview(transaction.state()), preview(transaction.nonce()),
                objectMapper.writeValueAsString(response.get("dcql_query")));
        return response;
    }

    @GetMapping("/api/presentations/{transactionId}")
    PresentationResult result(@PathVariable String transactionId) {
        Transaction transaction = store.find(transactionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown or expired presentation transaction"));
        PresentationResult response = switch (transaction.status()) {
            case PENDING -> new PresentationResult(
                    transaction.id(), "pending", transaction.profile().id(), null, Map.of(), null);
            case VERIFIED -> new PresentationResult(
                    transaction.id(), "verified", transaction.result().credentialType(),
                    transaction.result().issuer(), transaction.result().claims(), null);
            case FAILED -> new PresentationResult(
                    transaction.id(), "failed", transaction.profile().id(), null, Map.of(), transaction.error());
        };
        log.info("OID4VP presentation result response transaction_id={} status={} credential_type={} claims={} error={}",
                response.transactionId(), response.status(), response.credentialType(),
                response.claims().keySet(), response.error());
        return response;
    }

    @PostMapping(path = "/oid4vp/response", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    DirectPostResponse directPost(@RequestParam String state, @RequestParam("vp_token") String vpToken) {
        log.info("OID4VP direct_post request state={} vp_token={}", preview(state), tokenSummary(vpToken));
        Transaction transaction = store.findPendingByState(state)
                .orElseThrow(() -> new IllegalArgumentException("Unknown, expired, or already used state"));
        try {
            String presentation = presentationFor(vpToken, transaction.profile().id());
            log.info("OID4VP direct_post parsed transaction_id={} profile={} presentation={}",
                    transaction.id(), transaction.profile().id(), tokenSummary(presentation));
            PresentationStore.VerificationResult result = presentationVerifier.verify(presentation, transaction);
            if (!store.complete(transaction, result)) {
                throw new IllegalArgumentException("Presentation transaction was already completed");
            }
            DirectPostResponse response =
                    new DirectPostResponse(verifierBaseUrl + "/api/presentations/" + transaction.id());
            log.info("OID4VP direct_post response transaction_id={} redirect_uri={} status=verified",
                    transaction.id(), response.redirectUri());
            return response;
        } catch (IllegalArgumentException e) {
            store.fail(transaction, e.getMessage());
            log.info("OID4VP direct_post response transaction_id={} status=failed error={}",
                    transaction.id(), e.getMessage());
            throw e;
        }
    }

    @GetMapping("/.well-known/openid4vp-verifier")
    Map<String, Object> metadata() {
        return Map.of(
                "client_id", clientId,
                "response_uris", List.of(responseUri),
                "vp_formats_supported", clientMetadata().get("vp_formats_supported"));
    }

    private Map<String, Object> authorizationRequest(Transaction transaction) {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("client_id", clientId);
        request.put("response_type", "vp_token");
        request.put("response_mode", "direct_post");
        request.put("response_uri", responseUri);
        request.put("nonce", transaction.nonce());
        request.put("state", transaction.state());
        request.put("dcql_query", dcqlQuery(transaction.profile()));
        request.put("client_metadata", clientMetadata());
        return request;
    }

    private Map<String, Object> dcqlQuery(CredentialProfile profile) {
        List<Map<String, Object>> claims = profile.requiredClaims().stream()
                .map(claim -> Map.<String, Object>of("path", List.of(claim)))
                .toList();
        Map<String, Object> query = Map.of("credentials", List.of(Map.of(
                "id", profile.id(),
                "format", "dc+sd-jwt",
                "meta", Map.of("vct_values",
                        List.of(issuerUrl + "/credentials/types/" + profile.credentialTypeId())),
                "claims", claims,
                "require_cryptographic_holder_binding", true)));
        log.info("DCQL query built profile={} credential_type={} claims={} query={}",
                profile.id(), profile.credentialTypeId(), profile.requiredClaims(),
                objectMapper.writeValueAsString(query));
        return query;
    }

    private Map<String, Object> clientMetadata() {
        return Map.of("vp_formats_supported", Map.of(
                "dc+sd-jwt", Map.of(
                        "sd-jwt_alg_values", List.of("ES256"),
                        "kb-jwt_alg_values", List.of("ES256"))));
    }

    private String authorizationRequestUri(Map<String, Object> request) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString("openid4vp://authorize");
        request.forEach((name, value) -> builder.queryParam(
                name,
                value instanceof String string ? string : objectMapper.writeValueAsString(value)));
        return builder.build().encode().toUriString();
    }

    private String presentationFor(String vpToken, String credentialId) {
        JsonNode vpTokenJson;
        try {
            vpTokenJson = objectMapper.readTree(vpToken);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("vp_token is not valid JSON", e);
        }
        JsonNode presentations = vpTokenJson.get(credentialId);
        if (presentations == null || !presentations.isArray() || presentations.size() != 1
                || !presentations.get(0).isString()) {
            throw new IllegalArgumentException(
                    "vp_token must contain exactly one presentation for " + credentialId);
        }
        return presentations.get(0).asText();
    }

    private String preview(String value) {
        if (value == null || value.length() <= 12) {
            return value;
        }
        return value.substring(0, 6) + "..." + value.substring(value.length() - 6);
    }

    private String tokenSummary(String token) {
        return "len=" + token.length() + ", preview=" + preview(token);
    }
}
