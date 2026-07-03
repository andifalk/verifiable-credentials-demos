package dev.vcdemo.wallet.service;

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
import dev.vcdemo.wallet.model.CredentialType;
import dev.vcdemo.wallet.model.WalletCredential;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SdJwtServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SdJwtService service = new SdJwtService(objectMapper);

    @Test
    void presentationContainsOnlySelectedDisclosuresAndValidKeyBinding() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        String first = disclosure("given_name", "Erika");
        String second = disclosure("family_name", "Mustermann");
        WalletCredential credential = new WalletCredential(
                "id",
                CredentialType.PERSONAL_ID,
                "https://issuer.example",
                "header.payload.signature~" + first + "~" + second + "~",
                holderKey,
                service.parseDisclosures("header.payload.signature~" + first + "~" + second + "~"),
                Instant.now());

        String presentation = service.createPresentation(
                credential, List.of("given_name"), "https://verifier.example", "nonce-1");

        assertThat(presentation).contains("~" + first + "~");
        assertThat(presentation).doesNotContain(second);
        SignedJWT keyBindingJwt = SignedJWT.parse(presentation.substring(presentation.lastIndexOf('~') + 1));
        assertThat(keyBindingJwt.getHeader().getType()).isEqualTo(new JOSEObjectType("kb+jwt"));
        assertThat(keyBindingJwt.verify(new ECDSAVerifier(holderKey.toPublicJWK()))).isTrue();
        assertThat(keyBindingJwt.getJWTClaimsSet().getAudience()).contains("https://verifier.example");
        assertThat(keyBindingJwt.getJWTClaimsSet().getStringClaim("nonce")).isEqualTo("nonce-1");
        assertThat(keyBindingJwt.getJWTClaimsSet().getStringClaim("sd_hash")).isNotBlank();
    }

    @Test
    void issuanceProofUsesPublicHolderJwk() throws Exception {
        ECKey holderKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .generate();

        SignedJWT proof = SignedJWT.parse(
                service.createIssuanceProof(holderKey, "https://issuer.example", "nonce-1"));

        assertThat(proof.getHeader().getType()).isEqualTo(new JOSEObjectType("openid4vci-proof+jwt"));
        assertThat(proof.getHeader().getJWK().isPrivate()).isFalse();
        assertThat(proof.verify(new ECDSAVerifier(holderKey.toPublicJWK()))).isTrue();
    }

    private String disclosure(String name, Object value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                objectMapper.writeValueAsBytes(List.of("salt", name, value)));
    }
}
