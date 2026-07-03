package dev.vcdemo.wallet.model;

import com.nimbusds.jose.jwk.ECKey;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record WalletCredential(
        String id,
        CredentialType type,
        String issuer,
        String originalSdJwt,
        ECKey holderKey,
        List<Disclosure> disclosures,
        Instant receivedAt) {

    public record Disclosure(String claimName, Object claimValue, String encodedValue) {
    }

    public Map<String, Object> disclosedClaims() {
        return disclosures.stream().collect(java.util.stream.Collectors.toMap(
                Disclosure::claimName,
                Disclosure::claimValue,
                (left, right) -> left,
                java.util.LinkedHashMap::new));
    }
}
