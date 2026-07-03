package dev.vcdemo.wallet.service;

import dev.vcdemo.wallet.model.CredentialType;
import dev.vcdemo.wallet.model.WalletCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;

@Service
public class VerifierClient {

    private static final Logger log = LoggerFactory.getLogger(VerifierClient.class);

    private final RestClient restClient = RestClient.create();
    private final ObjectMapper objectMapper;
    private final SdJwtService sdJwtService;
    private final String verifierUrl;

    public VerifierClient(ObjectMapper objectMapper, SdJwtService sdJwtService,
            @Value("${wallet.verifier-url}") String verifierUrl) {
        this.objectMapper = objectMapper;
        this.sdJwtService = sdJwtService;
        this.verifierUrl = verifierUrl;
    }

    public PresentationOutcome present(WalletCredential credential, String presentationProfileId,
            List<String> selectedClaims) {
        try {
            CredentialType type = credential.type();
            type.presentationProfile(presentationProfileId);
            log.info("OID4VP wallet presentation creation request profile={} credential_id={} credential_type={} url={}",
                    presentationProfileId, credential.id(), type.id(),
                    verifierUrl + "/api/presentations/" + presentationProfileId);
            JsonNode created = restClient.post()
                    .uri(verifierUrl + "/api/presentations/" + presentationProfileId)
                    .retrieve()
                    .body(JsonNode.class);
            String transactionId = created.get("transaction_id").asText();
            log.info("OID4VP wallet presentation creation response transaction_id={} authorization_request_uri_len={} expires_in={}",
                    transactionId, created.path("authorization_request_uri").asText().length(),
                    created.path("expires_in").asText());
            log.info("OID4VP wallet authorization request fetch transaction_id={}", transactionId);
            JsonNode request = restClient.get()
                    .uri(verifierUrl + "/api/presentations/" + transactionId + "/request")
                    .retrieve()
                    .body(JsonNode.class);
            log.info("OID4VP wallet authorization request response transaction_id={} response_type={} response_mode={} state={} nonce={} dcql_query={}",
                    transactionId, request.path("response_type").asText(), request.path("response_mode").asText(),
                    preview(request.path("state").asText()), preview(request.path("nonce").asText()),
                    request.path("dcql_query").toString());
            validateRequest(request, type, presentationProfileId);

            String presentation = sdJwtService.createPresentation(
                    credential,
                    selectedClaims,
                    request.get("client_id").asText(),
                    request.get("nonce").asText());
            String vpToken = objectMapper.writeValueAsString(Map.of(presentationProfileId, List.of(presentation)));
            String form = "state=" + encode(request.get("state").asText())
                    + "&vp_token=" + encode(vpToken);
            log.info("OID4VP wallet direct_post request transaction_id={} response_uri={} selected_claims={} vp_token={}",
                    transactionId, request.get("response_uri").asText(), selectedClaims, tokenSummary(vpToken));
            restClient.post()
                    .uri(request.get("response_uri").asText())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .toBodilessEntity();
            log.info("OID4VP wallet direct_post response transaction_id={} accepted=true", transactionId);
            JsonNode result = restClient.get()
                    .uri(verifierUrl + "/api/presentations/" + transactionId)
                    .retrieve()
                    .body(JsonNode.class);
            log.info("OID4VP wallet presentation result response transaction_id={} status={} credential_type={} claims={} error={}",
                    transactionId, result.path("status").asText(), result.path("credential_type").asText(),
                    result.path("claims").toString(), result.path("error").asText(null));
            return new PresentationOutcome(transactionId, presentation, result);
        } catch (Exception e) {
            throw new IllegalStateException("Credential presentation failed: " + rootMessage(e), e);
        }
    }

    private void validateRequest(JsonNode request, CredentialType type, String presentationProfileId) {
        if (!"vp_token".equals(request.path("response_type").asText())
                || !"direct_post".equals(request.path("response_mode").asText())) {
            throw new IllegalArgumentException("Verifier requested an unsupported OID4VP response");
        }
        JsonNode credentialQuery = request.at("/dcql_query/credentials/0");
        if (!presentationProfileId.equals(credentialQuery.path("id").asText())
                || !supportsCredentialType(credentialQuery.at("/meta/vct_values"), type)
                || !"dc+sd-jwt".equals(credentialQuery.path("format").asText())) {
            throw new IllegalArgumentException("Verifier DCQL query does not match the credential");
        }
        log.info("DCQL wallet validation passed profile={} credential_type={} requested_vct_values={} requested_claims={}",
                presentationProfileId, type.id(), credentialQuery.at("/meta/vct_values"),
                credentialQuery.path("claims"));
    }

    private boolean supportsCredentialType(JsonNode vctValues, CredentialType type) {
        return vctValues.isArray() && StreamSupport.stream(vctValues.spliterator(), false)
                .anyMatch(value -> value.asText().endsWith("/credentials/types/" + type.id()));
    }

    private String encode(String value) {
        return org.springframework.web.util.UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8);
    }

    private String rootMessage(Exception exception) {
        Throwable current = exception;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current.getMessage();
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

    public record PresentationOutcome(String transactionId, String presentationSdJwt, JsonNode verifierResult) {
    }
}
