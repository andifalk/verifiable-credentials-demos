package dev.vcdemo.issuer.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.vcdemo.issuer.model.CredentialType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class SdJwtVcService {

    private static final Logger log = LoggerFactory.getLogger(SdJwtVcService.class);

    private final IssuerKeyService keys;
    private final ObjectMapper objectMapper;
    private final String issuer;
    private final Clock clock = Clock.systemUTC();

    public SdJwtVcService(IssuerKeyService keys, ObjectMapper objectMapper,
            @Value("${issuer.base-url}") String issuer) {
        this.keys = keys;
        this.objectMapper = objectMapper;
        this.issuer = issuer;
    }

    public String issue(CredentialType type, Map<String, Object> claims, Map<String, Object> holderJwk) {
        try {
            log.info("OID4VCI SD-JWT issuance start type={} available_claims={} holder_key_id={}",
                    type.configurationId(), claims.keySet(), holderJwk.get("kid"));
            List<String> disclosures = new ArrayList<>();
            List<String> digests = new ArrayList<>();
            for (String claimName : type.claims()) {
                if (!claims.containsKey(claimName)) {
                    log.info("OID4VCI SD-JWT disclosure skipped type={} claim={} reason=missing",
                            type.configurationId(), claimName);
                    continue;
                }
                String disclosure = encode(List.of(randomSalt(), claimName, claims.get(claimName)));
                disclosures.add(disclosure);
                digests.add(hash(disclosure));
                log.info("OID4VCI SD-JWT disclosure prepared type={} claim={} value_type={} digest={}",
                        type.configurationId(), claimName,
                        claims.get(claimName) == null ? "null" : claims.get(claimName).getClass().getSimpleName(),
                        digests.getLast());
            }

            Instant now = clock.instant();
            JWTClaimsSet payload = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(Duration.ofDays(365))))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("vct", issuer + "/credentials/types/" + type.configurationId())
                    .claim("_sd_alg", "sha-256")
                    .claim("_sd", digests)
                    .claim("cnf", Map.of("jwk", holderJwk))
                    .build();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("dc+sd-jwt"))
                    .keyID(keys.signingKey().getKeyID())
                    .build();
            SignedJWT signed = new SignedJWT(header, payload);
            signed.sign(new ECDSASigner(keys.signingKey()));
            String credential = signed.serialize() + "~" + String.join("~", disclosures) + "~";
            log.info("OID4VCI SD-JWT issuance complete type={} vct={} disclosures={} credential_len={}",
                    type.configurationId(), issuer + "/credentials/types/" + type.configurationId(),
                    disclosures.size(), credential.length());
            return credential;
        } catch (Exception e) {
            throw new IllegalStateException("Could not issue SD-JWT VC", e);
        }
    }

    private String randomSalt() {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
    }

    private String encode(Object value) throws JacksonException {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(objectMapper.writeValueAsBytes(value));
    }

    private String hash(String disclosure) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(disclosure.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
