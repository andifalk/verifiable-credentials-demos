package dev.vcdemo.verifier;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.vcdemo.verifier.model.CredentialProfile;
import dev.vcdemo.verifier.service.TrustedIssuerKeyResolver;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class PresentationFlowIntegrationTest {

    private static final String ISSUER = "http://localhost:8080";
    private static final String CLIENT_ID =
            "redirect_uri:http://localhost:8081/oid4vp/response";
    private static final ECKey ISSUER_KEY = generateKey("issuer-key");

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper objectMapper;

    @ParameterizedTest
    @EnumSource(CredentialProfile.class)
    void verifiesIssuerCredentialsThroughOid4vpDirectPost(CredentialProfile profile) throws Exception {
        JsonNode created = json(mvc.perform(post("/api/presentations/" + profile.id()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        String transactionId = created.get("transaction_id").asText();
        assertThat(created.get("authorization_request_uri").asText())
                .startsWith("openid4vp://authorize?");

        JsonNode request = json(mvc.perform(get("/api/presentations/" + transactionId + "/request"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        assertThat(request.get("response_type").asText()).isEqualTo("vp_token");
        assertThat(request.get("response_mode").asText()).isEqualTo("direct_post");
        assertThat(request.at("/dcql_query/credentials/0/format").asText()).isEqualTo("dc+sd-jwt");
        assertThat(request.at("/dcql_query/credentials/0/meta/vct_values/0").asText())
                .endsWith("/credentials/types/" + profile.credentialTypeId());

        ECKey holderKey = generateKey("holder-" + profile.id());
        String sdJwt = issueCredential(profile, holderKey);
        String presentation = sdJwt + keyBindingJwt(
                holderKey, request.get("nonce").asText(), hash(sdJwt));
        String vpToken = objectMapper.writeValueAsString(Map.of(
                profile.id(), List.of(presentation)));

        mvc.perform(post("/oid4vp/response")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("state", request.get("state").asText())
                        .param("vp_token", vpToken))
                .andExpect(status().isOk());

        JsonNode result = json(mvc.perform(get("/api/presentations/" + transactionId))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        assertThat(result.get("status").asText()).isEqualTo("verified");
        assertThat(result.get("issuer").asText()).isEqualTo(ISSUER);
        assertThat(result.get("credential_type").asText()).isEqualTo(profile.id());
        for (String claim : profile.requiredClaims()) {
            assertThat(result.get("claims").has(claim)).isTrue();
        }

        mvc.perform(post("/oid4vp/response")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("state", request.get("state").asText())
                        .param("vp_token", vpToken))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsAgeVerificationWhenAgeClaimIsFalse() throws Exception {
        JsonNode created = json(mvc.perform(post("/api/presentations/age_over_18"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        String transactionId = created.get("transaction_id").asText();
        JsonNode request = json(mvc.perform(get("/api/presentations/" + transactionId + "/request"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());

        ECKey holderKey = generateKey("holder-under-18");
        String sdJwt = issueCredential(
                CredentialProfile.AGE_OVER_18,
                holderKey,
                Map.of("is_over_18", false));
        String presentation = sdJwt + keyBindingJwt(
                holderKey, request.get("nonce").asText(), hash(sdJwt));
        String vpToken = objectMapper.writeValueAsString(Map.of(
                "age_over_18", List.of(presentation)));

        mvc.perform(post("/oid4vp/response")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("state", request.get("state").asText())
                        .param("vp_token", vpToken))
                .andExpect(status().isBadRequest());

        JsonNode result = json(mvc.perform(get("/api/presentations/" + transactionId))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        assertThat(result.get("status").asText()).isEqualTo("failed");
        assertThat(result.get("error").asText()).contains("not over 18");
    }

    private String issueCredential(CredentialProfile profile, ECKey holderKey) throws Exception {
        return issueCredential(profile, holderKey, claimValues(profile));
    }

    private String issueCredential(CredentialProfile profile, ECKey holderKey,
            Map<String, Object> values) throws Exception {
        List<String> disclosures = new ArrayList<>();
        List<String> digests = new ArrayList<>();
        for (String claim : profile.requiredClaims()) {
            String disclosure = encode(List.of(UUID.randomUUID().toString(), claim, values.get(claim)));
            disclosures.add(disclosure);
            digests.add(hash(disclosure));
        }
        Instant now = Instant.now();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("dc+sd-jwt"))
                        .keyID(ISSUER_KEY.getKeyID())
                        .build(),
                new JWTClaimsSet.Builder()
                        .issuer(ISSUER)
                        .issueTime(Date.from(now))
                        .expirationTime(Date.from(now.plusSeconds(3600)))
                        .claim("vct", ISSUER + "/credentials/types/" + profile.credentialTypeId())
                        .claim("_sd_alg", "sha-256")
                        .claim("_sd", digests)
                        .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()))
                        .build());
        jwt.sign(new ECDSASigner(ISSUER_KEY));
        return jwt.serialize() + "~" + String.join("~", disclosures) + "~";
    }

    private String keyBindingJwt(ECKey holderKey, String nonce, String sdHash) throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("kb+jwt"))
                        .build(),
                new JWTClaimsSet.Builder()
                        .audience(CLIENT_ID)
                        .issueTime(new Date())
                        .claim("nonce", nonce)
                        .claim("sd_hash", sdHash)
                        .build());
        jwt.sign(new ECDSASigner(holderKey));
        return jwt.serialize();
    }

    private Map<String, Object> claimValues(CredentialProfile profile) {
        Map<String, Object> values = new LinkedHashMap<>();
        profile.requiredClaims().forEach(claim -> values.put(claim,
                switch (claim) {
                    case "is_over_18" -> true;
                    case "vehicle_categories" -> List.of("B");
                    default -> "demo-" + claim;
                }));
        return values;
    }

    private String encode(Object value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(objectMapper.writeValueAsBytes(value));
    }

    private static String hash(String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private JsonNode json(String value) {
        return objectMapper.readTree(value);
    }

    private static ECKey generateKey(String keyId) {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .algorithm(JWSAlgorithm.ES256)
                    .keyID(keyId)
                    .generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @TestConfiguration
    static class IssuerTrustTestConfiguration {

        @Bean
        @Primary
        TrustedIssuerKeyResolver testIssuerKeyResolver() {
            return new TrustedIssuerKeyResolver(
                    ISSUER, ISSUER + "/jwks") {
                @Override
                public com.nimbusds.jose.jwk.JWK resolve(String issuer, String keyId) {
                    if (!ISSUER.equals(issuer) || !ISSUER_KEY.getKeyID().equals(keyId)) {
                        throw new IllegalArgumentException("Credential issuer or key is not trusted");
                    }
                    return ISSUER_KEY.toPublicJWK();
                }
            };
        }
    }
}
