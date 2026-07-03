package dev.vcdemo.verifier.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import dev.vcdemo.verifier.service.PresentationStore.Transaction;
import dev.vcdemo.verifier.service.PresentationStore.VerificationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class SdJwtPresentationVerifier {

    private static final Logger log = LoggerFactory.getLogger(SdJwtPresentationVerifier.class);

    private final TrustedIssuerKeyResolver issuerKeys;
    private final ObjectMapper objectMapper;
    private final String issuerUrl;
    private final String clientId;
    private final Clock clock = Clock.systemUTC();

    public SdJwtPresentationVerifier(TrustedIssuerKeyResolver issuerKeys, ObjectMapper objectMapper,
            @Value("${verifier.issuer-url}") String issuerUrl,
            @Value("${verifier.base-url}") String verifierBaseUrl) {
        this.issuerKeys = issuerKeys;
        this.objectMapper = objectMapper;
        this.issuerUrl = issuerUrl;
        this.clientId = "redirect_uri:" + verifierBaseUrl + "/oid4vp/response";
    }

    public VerificationResult verify(String presentation, Transaction transaction) {
        try {
            log.info("OID4VP verification start transaction_id={} profile={} required_claims={} presentation={}",
                    transaction.id(), transaction.profile().id(), transaction.profile().requiredClaims(),
                    tokenSummary(presentation));
            int keyBindingSeparator = presentation.lastIndexOf('~');
            if (keyBindingSeparator <= 0 || keyBindingSeparator == presentation.length() - 1) {
                throw new IllegalArgumentException("Presentation must be an SD-JWT with a Key Binding JWT");
            }
            String sdJwt = presentation.substring(0, keyBindingSeparator + 1);
            String keyBindingJwtValue = presentation.substring(keyBindingSeparator + 1);
            String[] sdJwtParts = sdJwt.split("~", -1);

            SignedJWT issuerSignedJwt = SignedJWT.parse(sdJwtParts[0]);
            validateIssuerJwt(issuerSignedJwt, transaction);
            Map<String, Object> claims = validateDisclosures(issuerSignedJwt, sdJwtParts);
            validateRequiredClaims(claims, transaction);
            validateProfileRules(claims, transaction);
            validateKeyBinding(issuerSignedJwt, keyBindingJwtValue, sdJwt, transaction);

            VerificationResult result = new VerificationResult(
                    issuerSignedJwt.getJWTClaimsSet().getIssuer(),
                    transaction.profile().id(),
                    Map.copyOf(claims));
            log.info("OID4VP verification complete transaction_id={} status=verified issuer={} credential_type={} disclosed_claims={}",
                    transaction.id(), result.issuer(), result.credentialType(), result.claims().keySet());
            return result;
        } catch (IllegalArgumentException e) {
            log.info("OID4VP verification failed transaction_id={} profile={} error={}",
                    transaction.id(), transaction.profile().id(), e.getMessage());
            throw e;
        } catch (Exception e) {
            log.info("OID4VP verification failed transaction_id={} profile={} error={}",
                    transaction.id(), transaction.profile().id(), e.getMessage());
            throw new IllegalArgumentException("Invalid SD-JWT presentation: " + e.getMessage(), e);
        }
    }

    private void validateIssuerJwt(SignedJWT jwt, Transaction transaction) throws Exception {
        if (!new JOSEObjectType("dc+sd-jwt").equals(jwt.getHeader().getType())
                || !JWSAlgorithm.ES256.equals(jwt.getHeader().getAlgorithm())) {
            throw new IllegalArgumentException("Unsupported issuer-signed JWT type or algorithm");
        }
        String issuer = jwt.getJWTClaimsSet().getIssuer();
        JWK key = issuerKeys.resolve(issuer, jwt.getHeader().getKeyID());
        if (!(key instanceof ECKey ecKey) || !jwt.verify(new ECDSAVerifier(ecKey))) {
            throw new IllegalArgumentException("Invalid credential issuer signature");
        }
        Instant now = clock.instant();
        Date expiresAt = jwt.getJWTClaimsSet().getExpirationTime();
        Date issuedAt = jwt.getJWTClaimsSet().getIssueTime();
        if (expiresAt == null || !expiresAt.toInstant().isAfter(now)) {
            throw new IllegalArgumentException("Credential is expired");
        }
        if (issuedAt == null || issuedAt.toInstant().isAfter(now.plusSeconds(30))) {
            throw new IllegalArgumentException("Credential issue time is invalid");
        }
        String expectedType = issuerUrl + "/credentials/types/" + transaction.profile().credentialTypeId();
        if (!expectedType.equals(jwt.getJWTClaimsSet().getStringClaim("vct"))) {
            throw new IllegalArgumentException("Credential type does not satisfy the DCQL query");
        }
        if (!"sha-256".equals(jwt.getJWTClaimsSet().getStringClaim("_sd_alg"))) {
            throw new IllegalArgumentException("Only SHA-256 disclosures are supported");
        }
        log.info("OID4VP issuer JWT validated transaction_id={} issuer={} vct={} key_id={} sd_alg=sha-256",
                transaction.id(), issuer, jwt.getJWTClaimsSet().getStringClaim("vct"),
                jwt.getHeader().getKeyID());
    }

    private Map<String, Object> validateDisclosures(SignedJWT jwt, String[] parts) throws Exception {
        List<String> expectedDigests = jwt.getJWTClaimsSet().getStringListClaim("_sd");
        if (expectedDigests == null) {
            throw new IllegalArgumentException("Credential has no selective disclosure digests");
        }
        Map<String, Object> claims = new LinkedHashMap<>();
        for (int index = 1; index < parts.length - 1; index++) {
            String encodedDisclosure = parts[index];
            if (encodedDisclosure.isBlank() || !expectedDigests.contains(hash(encodedDisclosure))) {
                throw new IllegalArgumentException("Disclosure digest is invalid");
            }
            List<?> disclosure = objectMapper.readValue(
                    Base64.getUrlDecoder().decode(encodedDisclosure),
                    List.class);
            if (disclosure.size() != 3 || !(disclosure.get(1) instanceof String name)) {
                throw new IllegalArgumentException("Disclosure structure is invalid");
            }
            if (claims.putIfAbsent(name, disclosure.get(2)) != null) {
                throw new IllegalArgumentException("Duplicate disclosed claim: " + name);
            }
            log.info("OID4VP disclosure validated claim={} value_type={} digest={}",
                    name,
                    disclosure.get(2) == null ? "null" : disclosure.get(2).getClass().getSimpleName(),
                    hash(encodedDisclosure));
        }
        return claims;
    }

    private void validateRequiredClaims(Map<String, Object> claims, Transaction transaction) {
        List<String> missing = transaction.profile().requiredClaims().stream()
                .filter(claim -> !claims.containsKey(claim))
                .toList();
        if (!missing.isEmpty()) {
            throw new IllegalArgumentException("Required claims were not disclosed: " + missing);
        }
        log.info("DCQL required claims satisfied transaction_id={} profile={} required_claims={}",
                transaction.id(), transaction.profile().id(), transaction.profile().requiredClaims());
    }

    private void validateProfileRules(Map<String, Object> claims, Transaction transaction) {
        if (transaction.profile().id().equals("age_over_18")
                && !Boolean.TRUE.equals(claims.get("is_over_18"))) {
            throw new IllegalArgumentException("Credential holder is not over 18");
        }
        if (transaction.profile().id().equals("age_over_18")) {
            log.info("DCQL age verification rule satisfied transaction_id={} is_over_18=true",
                    transaction.id());
        }
    }

    private void validateKeyBinding(SignedJWT issuerJwt, String compactKbJwt, String sdJwt,
            Transaction transaction) throws Exception {
        Map<String, Object> confirmation = issuerJwt.getJWTClaimsSet().getJSONObjectClaim("cnf");
        if (confirmation == null || !(confirmation.get("jwk") instanceof Map<?, ?> holderJwkValue)) {
            throw new IllegalArgumentException("Credential is not bound to a holder key");
        }
        @SuppressWarnings("unchecked")
        ECKey holderKey = ECKey.parse((Map<String, Object>) holderJwkValue);
        SignedJWT kbJwt = SignedJWT.parse(compactKbJwt);
        if (!new JOSEObjectType("kb+jwt").equals(kbJwt.getHeader().getType())
                || !JWSAlgorithm.ES256.equals(kbJwt.getHeader().getAlgorithm())
                || !kbJwt.verify(new ECDSAVerifier(holderKey))) {
            throw new IllegalArgumentException("Invalid Key Binding JWT");
        }
        if (!kbJwt.getJWTClaimsSet().getAudience().contains(clientId)) {
            throw new IllegalArgumentException("Key Binding JWT audience is invalid");
        }
        if (!transaction.nonce().equals(kbJwt.getJWTClaimsSet().getStringClaim("nonce"))) {
            throw new IllegalArgumentException("Key Binding JWT nonce is invalid");
        }
        Date issuedAt = kbJwt.getJWTClaimsSet().getIssueTime();
        if (issuedAt == null
                || Duration.between(issuedAt.toInstant(), clock.instant()).abs().toMinutes() > 5) {
            throw new IllegalArgumentException("Key Binding JWT issue time is invalid");
        }
        if (!hash(sdJwt).equals(kbJwt.getJWTClaimsSet().getStringClaim("sd_hash"))) {
            throw new IllegalArgumentException("Key Binding JWT sd_hash is invalid");
        }
        log.info("OID4VP key binding validated transaction_id={} audience={} nonce={} sd_hash={}",
                transaction.id(), clientId, preview(transaction.nonce()),
                kbJwt.getJWTClaimsSet().getStringClaim("sd_hash"));
    }

    private String hash(String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private String preview(String value) {
        if (value == null || value.length() <= 12) {
            return value;
        }
        return value.substring(0, 6) + "..." + value.substring(value.length() - 6);
    }

    private String tokenSummary(String token) {
        return "len=" + token.length() + ", preview=" + preview(token);
    }
}
