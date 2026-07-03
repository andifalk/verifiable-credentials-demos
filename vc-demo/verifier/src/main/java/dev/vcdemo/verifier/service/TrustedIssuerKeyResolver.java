package dev.vcdemo.verifier.service;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.text.ParseException;

@Service
public class TrustedIssuerKeyResolver {

    private final RestClient restClient;
    private final String trustedIssuer;
    private final String jwksUri;

    public TrustedIssuerKeyResolver(@Value("${verifier.issuer-url}") String trustedIssuer,
            @Value("${verifier.issuer-jwks-uri}") String jwksUri) {
        this.restClient = RestClient.create();
        this.trustedIssuer = trustedIssuer;
        this.jwksUri = jwksUri;
    }

    public JWK resolve(String issuer, String keyId) {
        if (!trustedIssuer.equals(issuer)) {
            throw new IllegalArgumentException("Credential issuer is not trusted");
        }
        String json = restClient.get().uri(jwksUri).retrieve().body(String.class);
        try {
            JWK key = JWKSet.parse(json).getKeyByKeyId(keyId);
            if (key == null) {
                throw new IllegalArgumentException("Issuer signing key was not found");
            }
            return key;
        } catch (ParseException e) {
            throw new IllegalArgumentException("Issuer returned an invalid JWKS", e);
        }
    }
}
