package dev.vcdemo.issuer;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.vcdemo.issuer.model.CredentialType;
import dev.vcdemo.issuer.service.IssuerKeyService;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class IssuanceFlowIntegrationTest {

    private static final String ISSUER = "http://localhost:8080";
    private static final String GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    IssuerKeyService issuerKeys;

    @ParameterizedTest
    @EnumSource(CredentialType.class)
    void issuesEachDemoCredentialThroughOid4vciFlow(CredentialType type) throws Exception {
        JsonNode metadata = json(mvc.perform(get("/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(metadata.at("/credential_configurations_supported/" + type.configurationId() + "/format")
                .asText()).isEqualTo("dc+sd-jwt");

        JsonNode createdOffer = json(mvc.perform(post("/demo/offers/" + type.configurationId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        String code = createdOffer.get("pre_authorized_code").asText();

        JsonNode token = json(mvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", GRANT)
                        .param("pre-authorized_code", code))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());

        JsonNode nonce = json(mvc.perform(post("/nonce"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        ECKey walletKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        String proof = walletProof(walletKey, nonce.get("c_nonce").asText());
        String request = objectMapper.writeValueAsString(Map.of(
                "credential_configuration_id", type.configurationId(),
                "proofs", Map.of("jwt", List.of(proof))));

        JsonNode response = json(mvc.perform(post("/credential")
                        .header("Authorization", "Bearer " + token.get("access_token").asText())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());

        String credential = response.at("/credentials/0/credential").asText();
        String[] parts = credential.split("~");
        SignedJWT issuerSignedJwt = SignedJWT.parse(parts[0]);
        assertThat(issuerSignedJwt.verify(new ECDSAVerifier(issuerKeys.signingKey().toPublicJWK()))).isTrue();
        assertThat(issuerSignedJwt.getJWTClaimsSet().getStringClaim("vct"))
                .endsWith("/credentials/types/" + type.configurationId());
        assertThat(parts.length).isEqualTo(type.claims().size() + 1);
    }

    private String walletProof(ECKey key, String nonce) throws Exception {
        SignedJWT proof = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("openid4vci-proof+jwt"))
                        .jwk(key.toPublicJWK())
                        .build(),
                new JWTClaimsSet.Builder()
                        .audience(ISSUER)
                        .issueTime(Date.from(Instant.now()))
                        .claim("nonce", nonce)
                        .build());
        proof.sign(new ECDSASigner(key));
        return proof.serialize();
    }

    private JsonNode json(String value) {
        return objectMapper.readTree(value);
    }
}
