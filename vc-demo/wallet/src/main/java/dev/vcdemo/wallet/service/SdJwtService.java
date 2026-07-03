package dev.vcdemo.wallet.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.vcdemo.wallet.model.CredentialType;
import dev.vcdemo.wallet.model.WalletCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Service
public class SdJwtService {

    private static final Logger log = LoggerFactory.getLogger(SdJwtService.class);

    private final ObjectMapper objectMapper;

    public SdJwtService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public List<WalletCredential.Disclosure> parseDisclosures(String sdJwt) {
        try {
            String[] parts = sdJwt.split("~", -1);
            if (parts.length < 2) {
                throw new IllegalArgumentException("Credential is not an SD-JWT");
            }
            List<WalletCredential.Disclosure> disclosures = new ArrayList<>();
            for (int index = 1; index < parts.length; index++) {
                if (parts[index].isBlank()) {
                    continue;
                }
                List<?> disclosure = objectMapper.readValue(
                        Base64.getUrlDecoder().decode(parts[index]), List.class);
                if (disclosure.size() != 3 || !(disclosure.get(1) instanceof String claimName)) {
                    throw new IllegalArgumentException("Invalid SD-JWT disclosure");
                }
                disclosures.add(new WalletCredential.Disclosure(claimName, disclosure.get(2), parts[index]));
            }
            List<WalletCredential.Disclosure> parsed = List.copyOf(disclosures);
            log.info("SD-JWT wallet parsed disclosures claims={}",
                    parsed.stream().map(WalletCredential.Disclosure::claimName).toList());
            return parsed;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Could not parse SD-JWT disclosures", e);
        }
    }

    public void validateIssuedCredential(String sdJwt, String expectedIssuer, CredentialType type,
            ECKey holderKey, JWKSet issuerKeys) {
        try {
            String[] parts = sdJwt.split("~", -1);
            SignedJWT jwt = SignedJWT.parse(parts[0]);
            if (!new JOSEObjectType("dc+sd-jwt").equals(jwt.getHeader().getType())
                    || !JWSAlgorithm.ES256.equals(jwt.getHeader().getAlgorithm())) {
                throw new IllegalArgumentException("Unsupported issued credential type or algorithm");
            }
            var issuerKey = issuerKeys.getKeyByKeyId(jwt.getHeader().getKeyID());
            if (!(issuerKey instanceof ECKey ecKey)
                    || !jwt.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(ecKey))) {
                throw new IllegalArgumentException("Invalid issuer signature");
            }
            if (!expectedIssuer.equals(jwt.getJWTClaimsSet().getIssuer())
                    || !expectedIssuer.concat("/credentials/types/").concat(type.id())
                            .equals(jwt.getJWTClaimsSet().getStringClaim("vct"))) {
                throw new IllegalArgumentException("Issued credential has an unexpected issuer or type");
            }
            if (jwt.getJWTClaimsSet().getExpirationTime() == null
                    || !jwt.getJWTClaimsSet().getExpirationTime().toInstant().isAfter(Instant.now())) {
                throw new IllegalArgumentException("Issued credential is expired");
            }
            Object boundJwk = jwt.getJWTClaimsSet().getJSONObjectClaim("cnf").get("jwk");
            if (!holderKey.toPublicJWK().toJSONObject().equals(boundJwk)) {
                throw new IllegalArgumentException("Issued credential is bound to a different holder key");
            }
            List<String> digests = jwt.getJWTClaimsSet().getStringListClaim("_sd");
            log.info("OID4VCI wallet issued credential validation issuer={} type={} key_id={} disclosure_digests={}",
                    jwt.getJWTClaimsSet().getIssuer(), type.id(), jwt.getHeader().getKeyID(),
                    digests == null ? 0 : digests.size());
            for (int index = 1; index < parts.length - 1; index++) {
                if (!digests.contains(hash(parts[index]))) {
                    throw new IllegalArgumentException("Issued credential contains an invalid disclosure");
                }
            }
            log.info("OID4VCI wallet issued credential validation complete type={} disclosures={}",
                    type.id(), Math.max(0, parts.length - 2));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Could not validate issued credential", e);
        }
    }

    public String createPresentation(WalletCredential credential, List<String> selectedClaims,
            String audience, String nonce) {
        try {
            Set<String> selected = new LinkedHashSet<>(selectedClaims);
            List<String> disclosures = credential.disclosures().stream()
                    .filter(disclosure -> selected.contains(disclosure.claimName()))
                    .map(WalletCredential.Disclosure::encodedValue)
                    .toList();
            log.info("OID4VP wallet presentation build credential_id={} credential_type={} selected_claims={} selected_disclosures={}",
                    credential.id(), credential.type().id(), selected, disclosures.size());
            String issuerJwt = credential.originalSdJwt().substring(
                    0, credential.originalSdJwt().indexOf('~'));
            String sdJwt = issuerJwt + "~" + String.join("~", disclosures) + "~";
            SignedJWT keyBindingJwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("kb+jwt"))
                            .build(),
                    new JWTClaimsSet.Builder()
                            .audience(audience)
                            .issueTime(Date.from(Instant.now()))
                            .claim("nonce", nonce)
                            .claim("sd_hash", hash(sdJwt))
                            .build());
            keyBindingJwt.sign(new ECDSASigner(credential.holderKey()));
            String presentation = sdJwt + keyBindingJwt.serialize();
            log.info("OID4VP wallet presentation built credential_id={} sd_jwt_len={} kb_jwt_len={} presentation_len={} audience={} nonce={}",
                    credential.id(), sdJwt.length(), keyBindingJwt.serialize().length(), presentation.length(),
                    audience, preview(nonce));
            return presentation;
        } catch (Exception e) {
            throw new IllegalStateException("Could not create SD-JWT presentation", e);
        }
    }

    public String createIssuanceProof(ECKey holderKey, String issuer, String nonce) {
        try {
            SignedJWT proof = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("openid4vci-proof+jwt"))
                            .jwk(holderKey.toPublicJWK())
                            .build(),
                    new JWTClaimsSet.Builder()
                            .audience(issuer)
                            .issueTime(new Date())
                            .claim("nonce", nonce)
                            .build());
            proof.sign(new ECDSASigner(holderKey));
            String serialized = proof.serialize();
            log.info("OID4VCI wallet proof built audience={} nonce={} holder_key_id={} proof_len={}",
                    issuer, preview(nonce), holderKey.getKeyID(), serialized.length());
            return serialized;
        } catch (Exception e) {
            throw new IllegalStateException("Could not create OID4VCI wallet proof", e);
        }
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
}
