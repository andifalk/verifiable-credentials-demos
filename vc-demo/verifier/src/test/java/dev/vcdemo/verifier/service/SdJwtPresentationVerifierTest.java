package dev.vcdemo.verifier.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import dev.vcdemo.verifier.model.CredentialProfile;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SdJwtPresentationVerifierTest {

    @Test
    void rejectsCredentialWithoutKeyBindingJwt() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        TrustedIssuerKeyResolver resolver = new TrustedIssuerKeyResolver(
                "https://issuer.example",
                "https://issuer.example/jwks") {
            @Override
            public com.nimbusds.jose.jwk.JWK resolve(String issuer, String keyId) {
                return issuerKey.toPublicJWK();
            }
        };
        SdJwtPresentationVerifier verifier = new SdJwtPresentationVerifier(
                resolver, new ObjectMapper(), "https://issuer.example", "https://verifier.example");
        PresentationStore.Transaction transaction =
                new PresentationStore().create(CredentialProfile.PERSONAL_ID);

        assertThatThrownBy(() -> verifier.verify("not-a-presentation", transaction))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Key Binding JWT");
    }
}
