package dev.vcdemo.issuer.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WalletProofServiceTest {

    private static final String ISSUER = "https://issuer.example";

    private final WalletProofService service = new WalletProofService(new IssuanceStore(), ISSUER);

    @Test
    void rejectsProofWithoutPublicJwk() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        SignedJWT proof = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("openid4vci-proof+jwt"))
                        .build(),
                new JWTClaimsSet.Builder()
                        .audience(ISSUER)
                        .issueTime(Date.from(Instant.now()))
                        .build());
        proof.sign(new ECDSASigner(key));

        assertThatThrownBy(() -> service.validate(proof.serialize()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Proof header must contain a public JWK");
    }
}
