package dev.vcdemo.issuer.web;

import dev.vcdemo.issuer.model.CredentialType;
import dev.vcdemo.issuer.model.ProtocolModels.CreateOfferRequest;
import dev.vcdemo.issuer.model.ProtocolModels.CredentialRequest;
import dev.vcdemo.issuer.model.ProtocolModels.CredentialResponse;
import dev.vcdemo.issuer.model.ProtocolModels.IssuedCredential;
import dev.vcdemo.issuer.model.ProtocolModels.OfferCreated;
import dev.vcdemo.issuer.service.IssuanceStore;
import dev.vcdemo.issuer.service.SdJwtVcService;
import dev.vcdemo.issuer.service.WalletProofService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class IssuanceController {

    private static final Logger log = LoggerFactory.getLogger(IssuanceController.class);

    static final String PRE_AUTHORIZED_GRANT =
            "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    private final String issuer;
    private final IssuanceStore store;
    private final WalletProofService proofService;
    private final SdJwtVcService credentialService;

    public IssuanceController(@Value("${issuer.base-url}") String issuer, IssuanceStore store,
            WalletProofService proofService, SdJwtVcService credentialService) {
        this.issuer = issuer;
        this.store = store;
        this.proofService = proofService;
        this.credentialService = credentialService;
    }

    @PostMapping("/demo/offers/{configurationId}")
    OfferCreated createOffer(@PathVariable String configurationId,
            @RequestBody(required = false) CreateOfferRequest request) {
        log.info("OID4VCI offer request configuration_id={} requested_claims={}",
                configurationId, request == null ? null : request.claims());
        CredentialType type = CredentialType.fromConfigurationId(configurationId);
        IssuanceStore.CreatedOffer created = store.createOffer(type, request == null ? null : request.claims());
        Map<String, Object> offer = offer(created.offer());
        OfferCreated response = new OfferCreated(issuer + "/credential-offer/" + created.id(), created.code(), offer);
        log.info("OID4VCI offer response offer_id={} credential_configuration_ids={} pre_authorized_code={}",
                created.id(), offer.get("credential_configuration_ids"), preview(created.code()));
        return response;
    }

    @GetMapping("/credential-offer/{id}")
    Map<String, Object> credentialOffer(@PathVariable String id) {
        log.info("OID4VCI credential offer fetch request offer_id={}", id);
        return store.findOffer(id).map(offer -> {
            Map<String, Object> response = offer(offer);
            log.info("OID4VCI credential offer fetch response offer_id={} type={}",
                    id, offer.type().configurationId());
            return response;
        })
                .orElseThrow(() -> new IllegalArgumentException("Unknown or expired credential offer"));
    }

    @PostMapping(path = "/oauth2/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    Map<String, Object> token(@RequestParam("grant_type") String grantType,
            @RequestParam("pre-authorized_code") String code) {
        log.info("OID4VCI token request grant_type={} pre_authorized_code={}", grantType, preview(code));
        if (!PRE_AUTHORIZED_GRANT.equals(grantType)) {
            throw new IllegalArgumentException("Unsupported grant_type");
        }
        String accessToken = store.exchangeCode(code)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or already used pre-authorized code"));
        Map<String, Object> response = Map.of(
                "access_token", accessToken,
                "token_type", "Bearer",
                "expires_in", 300);
        log.info("OID4VCI token response token_type=Bearer expires_in=300 access_token={}",
                preview(accessToken));
        return response;
    }

    @PostMapping("/nonce")
    Map<String, Object> nonce() {
        String nonce = store.createNonce();
        log.info("OID4VCI nonce response c_nonce={}", preview(nonce));
        return Map.of("c_nonce", nonce);
    }

    @PostMapping("/credential")
    CredentialResponse credential(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
            @Valid @RequestBody CredentialRequest request) {
        log.info("OID4VCI credential request configuration_id={} proofs.jwt.count={} authorization={}",
                request.credentialConfigurationId(),
                request.proofs() == null || request.proofs().jwt() == null ? 0 : request.proofs().jwt().size(),
                authorization == null ? null : "Bearer " + preview(bearerToken(authorization)));
        String token = bearerToken(authorization);
        IssuanceStore.AccessGrant grant = store.accessGrant(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired access token"));
        if (!grant.type().configurationId().equals(request.credentialConfigurationId())) {
            throw new IllegalArgumentException("Credential configuration was not authorized by the offer");
        }
        if (request.proofs() == null || request.proofs().jwt() == null || request.proofs().jwt().size() != 1) {
            throw new IllegalArgumentException("Exactly one JWT proof is required");
        }
        Map<String, Object> holderJwk = proofService.validate(request.proofs().jwt().getFirst());
        String credential = credentialService.issue(grant.type(), grant.claims(), holderJwk);
        CredentialResponse response = new CredentialResponse(List.of(new IssuedCredential(credential)));
        log.info("OID4VCI credential response configuration_id={} credential_count=1 credential={}",
                grant.type().configurationId(), tokenSummary(credential));
        return response;
    }

    private Map<String, Object> offer(IssuanceStore.Offer offer) {
        return Map.of(
                "credential_issuer", issuer,
                "credential_configuration_ids", List.of(offer.type().configurationId()),
                "grants", Map.of(PRE_AUTHORIZED_GRANT, Map.of(
                        "pre-authorized_code", offer.preAuthorizedCode())));
    }

    private String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Bearer access token is required");
        }
        return authorization.substring("Bearer ".length());
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
