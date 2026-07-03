package dev.vcdemo.wallet.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
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

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
public class IssuerClient {

    private static final Logger log = LoggerFactory.getLogger(IssuerClient.class);

    private static final String PRE_AUTHORIZED_GRANT =
            "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    private final RestClient restClient = RestClient.create();
    private final ObjectMapper objectMapper;
    private final SdJwtService sdJwtService;
    private final String issuerUrl;

    public IssuerClient(ObjectMapper objectMapper, SdJwtService sdJwtService,
            @Value("${wallet.issuer-url}") String issuerUrl) {
        this.objectMapper = objectMapper;
        this.sdJwtService = sdJwtService;
        this.issuerUrl = issuerUrl;
    }

    public WalletCredential issue(CredentialType type) {
        try {
            log.info("OID4VCI wallet offer request type={} url={}", type.id(),
                    issuerUrl + "/demo/offers/" + type.id());
            JsonNode offer = postJson(issuerUrl + "/demo/offers/" + type.id(), Map.of());
            String code = offer.get("pre_authorized_code").asText();
            log.info("OID4VCI wallet offer response type={} offer_uri={} credential_offer={} pre_authorized_code={}",
                    type.id(), offer.path("offer_uri").asText(null),
                    offer.path("credential_offer").toString(), preview(code));
            log.info("OID4VCI wallet token request grant_type={} pre_authorized_code={}",
                    PRE_AUTHORIZED_GRANT, preview(code));
            JsonNode token = postForm(issuerUrl + "/oauth2/token", Map.of(
                    "grant_type", PRE_AUTHORIZED_GRANT,
                    "pre-authorized_code", code));
            log.info("OID4VCI wallet token response token_type={} expires_in={} access_token={}",
                    token.path("token_type").asText(), token.path("expires_in").asText(),
                    preview(token.path("access_token").asText()));
            log.info("OID4VCI wallet nonce request url={}", issuerUrl + "/nonce");
            JsonNode nonce = postJson(issuerUrl + "/nonce", null);
            log.info("OID4VCI wallet nonce response c_nonce={}", preview(nonce.get("c_nonce").asText()));

            ECKey holderKey = new ECKeyGenerator(Curve.P_256)
                    .algorithm(JWSAlgorithm.ES256)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            String proof = sdJwtService.createIssuanceProof(
                    holderKey, issuerUrl, nonce.get("c_nonce").asText());
            log.info("OID4VCI wallet credential request configuration_id={} proof_jwt={} holder_key_id={}",
                    type.id(), tokenSummary(proof), holderKey.getKeyID());
            JsonNode response = restClient.post()
                    .uri(issuerUrl + "/credential")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + token.get("access_token").asText())
                    .body(Map.of(
                            "credential_configuration_id", type.id(),
                            "proofs", Map.of("jwt", java.util.List.of(proof))))
                    .retrieve()
                    .body(JsonNode.class);
            String credential = response.at("/credentials/0/credential").asText();
            log.info("OID4VCI wallet credential response credential_count={} credential={}",
                    response.path("credentials").size(), tokenSummary(credential));
            String issuer = SignedJWT.parse(credential.substring(0, credential.indexOf('~')))
                    .getJWTClaimsSet().getIssuer();
            log.info("OID4VCI wallet issuer JWKS request url={}", issuerUrl + "/jwks");
            String jwks = restClient.get()
                    .uri(issuerUrl + "/jwks")
                    .retrieve()
                    .body(String.class);
            log.info("OID4VCI wallet issuer JWKS response len={}", jwks.length());
            sdJwtService.validateIssuedCredential(
                    credential, issuerUrl, type, holderKey, JWKSet.parse(jwks));
            WalletCredential stored = new WalletCredential(
                    UUID.randomUUID().toString(),
                    type,
                    issuer,
                    credential,
                    holderKey,
                    sdJwtService.parseDisclosures(credential),
                    Instant.now());
            log.info("OID4VCI wallet stored credential id={} type={} issuer={} disclosures={}",
                    stored.id(), stored.type().id(), stored.issuer(),
                    stored.disclosures().stream().map(WalletCredential.Disclosure::claimName).toList());
            return stored;
        } catch (Exception e) {
            throw new IllegalStateException("Credential issuance failed: " + rootMessage(e), e);
        }
    }

    private JsonNode postJson(String uri, Object body) {
        RestClient.RequestBodySpec request = restClient.post().uri(uri).contentType(MediaType.APPLICATION_JSON);
        if (body != null) {
            request.body(body);
        }
        return request.retrieve().body(JsonNode.class);
    }

    private JsonNode postForm(String uri, Map<String, String> values) {
        String form = values.entrySet().stream()
                .map(entry -> org.springframework.web.util.UriUtils.encodeQueryParam(
                        entry.getKey(), java.nio.charset.StandardCharsets.UTF_8)
                        + "=" + org.springframework.web.util.UriUtils.encodeQueryParam(
                        entry.getValue(), java.nio.charset.StandardCharsets.UTF_8))
                .collect(java.util.stream.Collectors.joining("&"));
        String response = restClient.post()
                .uri(uri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(String.class);
        return objectMapper.readTree(response);
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
}
