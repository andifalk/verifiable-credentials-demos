package dev.vcdemo.issuer.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class WalletProofService {

    private final IssuanceStore store;
    private final String issuer;
    private final Clock clock = Clock.systemUTC();

    public WalletProofService(IssuanceStore store, @Value("${issuer.base-url}") String issuer) {
        this.store = store;
        this.issuer = issuer;
    }

    public Map<String, Object> validate(String compactProof) {
        try {
            SignedJWT proof = SignedJWT.parse(compactProof);
            if (proof.getHeader().getType() == null
                    || !"openid4vci-proof+jwt".equals(proof.getHeader().getType().toString())) {
                throw new BadJOSEException("Invalid proof typ");
            }
            if (!JWSAlgorithm.ES256.equals(proof.getHeader().getAlgorithm())) {
                throw new BadJOSEException("Only ES256 wallet proofs are supported");
            }
            JWK headerJwk = proof.getHeader().getJWK();
            if (headerJwk == null) {
                throw new BadJOSEException("Proof header must contain a public JWK");
            }
            ECKey publicKey = ECKey.parse(headerJwk.toJSONObject());
            if (publicKey.isPrivate()) {
                throw new BadJOSEException("Proof header must contain a public JWK");
            }
            if (!proof.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(publicKey))) {
                throw new BadJOSEException("Invalid wallet proof signature");
            }
            List<String> audience = proof.getJWTClaimsSet().getAudience();
            String nonce = proof.getJWTClaimsSet().getStringClaim("nonce");
            Date issuedAt = proof.getJWTClaimsSet().getIssueTime();
            Instant now = clock.instant();
            if (!audience.contains(issuer)) {
                throw new BadJOSEException("Proof audience does not identify this issuer");
            }
            if (issuedAt == null || Duration.between(issuedAt.toInstant(), now).abs().toMinutes() > 5) {
                throw new BadJOSEException("Proof iat is outside the accepted window");
            }
            if (nonce == null || !store.consumeNonce(nonce)) {
                throw new BadJOSEException("Proof nonce is missing, expired, or already used");
            }
            return publicKey.toPublicJWK().toJSONObject();
        } catch (ParseException | com.nimbusds.jose.JOSEException | BadJOSEException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }
}
