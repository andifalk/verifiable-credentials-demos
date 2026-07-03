package dev.vcdemo.issuer.service;

import dev.vcdemo.issuer.model.CredentialType;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class IssuanceStore {

    private static final Duration LIFETIME = Duration.ofMinutes(5);

    private final Map<String, Offer> offers = new ConcurrentHashMap<>();
    private final Map<String, AccessGrant> accessTokens = new ConcurrentHashMap<>();
    private final Map<String, Nonce> nonces = new ConcurrentHashMap<>();
    private final Clock clock;

    public IssuanceStore() {
        this(Clock.systemUTC());
    }

    IssuanceStore(Clock clock) {
        this.clock = clock;
    }

    public CreatedOffer createOffer(CredentialType type, Map<String, Object> requestedClaims) {
        String id = randomValue();
        String code = randomValue();
        Map<String, Object> claims = requestedClaims == null || requestedClaims.isEmpty()
                ? type.sampleClaims()
                : Map.copyOf(requestedClaims);
        Offer offer = new Offer(id, code, type, claims, clock.instant().plus(LIFETIME));
        offers.put(id, offer);
        return new CreatedOffer(id, code, offer);
    }

    public Optional<Offer> findOffer(String id) {
        return Optional.ofNullable(offers.get(id)).filter(this::valid);
    }

    public Optional<String> exchangeCode(String code) {
        Optional<Offer> match = offers.values().stream()
                .filter(this::valid)
                .filter(offer -> offer.preAuthorizedCode().equals(code))
                .findFirst();
        if (match.isEmpty() || !offers.remove(match.get().id(), match.get())) {
            return Optional.empty();
        }
        String token = randomValue();
        accessTokens.put(token, new AccessGrant(match.get().type(), match.get().claims(),
                clock.instant().plus(LIFETIME)));
        return Optional.of(token);
    }

    public Optional<AccessGrant> accessGrant(String token) {
        return Optional.ofNullable(accessTokens.get(token)).filter(grant -> grant.expiresAt().isAfter(clock.instant()));
    }

    public String createNonce() {
        String nonce = randomValue();
        nonces.put(nonce, new Nonce(clock.instant().plus(LIFETIME), false));
        return nonce;
    }

    public boolean consumeNonce(String nonce) {
        Nonce current = nonces.get(nonce);
        if (current == null || current.used() || !current.expiresAt().isAfter(clock.instant())) {
            return false;
        }
        return nonces.replace(nonce, current, new Nonce(current.expiresAt(), true));
    }

    private boolean valid(Offer offer) {
        return offer.expiresAt().isAfter(clock.instant());
    }

    private String randomValue() {
        return UUID.randomUUID() + "." + UUID.randomUUID();
    }

    public record CreatedOffer(String id, String code, Offer offer) {
    }

    public record Offer(String id, String preAuthorizedCode, CredentialType type, Map<String, Object> claims,
            Instant expiresAt) {
    }

    public record AccessGrant(CredentialType type, Map<String, Object> claims, Instant expiresAt) {
    }

    private record Nonce(Instant expiresAt, boolean used) {
    }
}
