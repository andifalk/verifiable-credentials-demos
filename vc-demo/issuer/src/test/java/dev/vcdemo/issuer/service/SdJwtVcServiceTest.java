package dev.vcdemo.issuer.service;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import dev.vcdemo.issuer.model.CredentialType;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtVcServiceTest {

    private final IssuerKeyService keys = new IssuerKeyService();
    private final SdJwtVcService service =
            new SdJwtVcService(keys, new ObjectMapper(), "https://issuer.example");

    @Test
    void createsSignedSdJwtVcWithSelectiveDisclosuresAndHolderBinding() throws Exception {
        Map<String, Object> holderJwk = Map.of(
                "kty", "EC",
                "crv", "P-256",
                "x", "f83OJ3D2xF4RPA9WrW5Ofp8YbGqVQx7nB4R20DFAu4g",
                "y", "x_FEzRu9m36HLNF3Obv0XGxH-9QH2Q8fQ1A6q5M4fXQ");

        String credential = service.issue(
                CredentialType.PERSONAL_ID,
                CredentialType.PERSONAL_ID.sampleClaims(),
                holderJwk);

        String[] parts = credential.split("~");
        SignedJWT issuerSignedJwt = SignedJWT.parse(parts[0]);
        assertThat(issuerSignedJwt.getHeader().getType().toString()).isEqualTo("dc+sd-jwt");
        assertThat(issuerSignedJwt.verify(new ECDSAVerifier(keys.signingKey().toPublicJWK()))).isTrue();
        assertThat(issuerSignedJwt.getJWTClaimsSet().getStringClaim("vct"))
                .isEqualTo("https://issuer.example/credentials/types/personal_id");
        assertThat(issuerSignedJwt.getJWTClaimsSet().getJSONObjectClaim("cnf").get("jwk"))
                .isEqualTo(holderJwk);
        assertThat(parts).hasSize(1 + CredentialType.PERSONAL_ID.claims().size());

        List<?> disclosure = new ObjectMapper().readValue(
                new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8),
                List.class);
        assertThat(disclosure).hasSize(3);
        assertThat(CredentialType.PERSONAL_ID.claims()).contains(String.valueOf(disclosure.get(1)));
    }
}
