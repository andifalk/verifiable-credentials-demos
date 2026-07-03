package dev.vcdemo.issuer.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Service
public class IssuerKeyService {

    private final ECKey signingKey;

    public IssuerKeyService() {
        try {
            this.signingKey = new ECKeyGeneratorCompat().generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot generate issuer key", e);
        }
    }

    public ECKey signingKey() {
        return signingKey;
    }

    public Map<String, Object> publicJwkSet() {
        return new JWKSet(signingKey.toPublicJWK()).toJSONObject();
    }

    private static final class ECKeyGeneratorCompat {
        ECKey generate() throws JOSEException {
            return new com.nimbusds.jose.jwk.gen.ECKeyGenerator(Curve.P_256)
                    .algorithm(JWSAlgorithm.ES256)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        }
    }
}
