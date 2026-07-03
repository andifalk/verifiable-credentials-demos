package dev.vcdemo.verifier.service;

import dev.vcdemo.verifier.model.CredentialProfile;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class PresentationStore {

    private static final Duration LIFETIME = Duration.ofMinutes(5);

    private final Map<String, Transaction> transactions = new ConcurrentHashMap<>();
    private final Clock clock;

    public PresentationStore() {
        this(Clock.systemUTC());
    }

    PresentationStore(Clock clock) {
        this.clock = clock;
    }

    public Transaction create(CredentialProfile profile) {
        String id = randomValue();
        Transaction transaction = new Transaction(
                id,
                randomValue(),
                randomValue(),
                profile,
                clock.instant().plus(LIFETIME),
                Status.PENDING,
                null,
                null);
        transactions.put(id, transaction);
        return transaction;
    }

    public Optional<Transaction> find(String id) {
        return Optional.ofNullable(transactions.get(id)).filter(this::notExpired);
    }

    public Optional<Transaction> findPendingByState(String state) {
        return transactions.values().stream()
                .filter(this::notExpired)
                .filter(transaction -> transaction.status() == Status.PENDING)
                .filter(transaction -> transaction.state().equals(state))
                .findFirst();
    }

    public boolean complete(Transaction current, VerificationResult result) {
        Transaction completed = new Transaction(
                current.id(), current.state(), current.nonce(), current.profile(), current.expiresAt(),
                Status.VERIFIED, result, null);
        return transactions.replace(current.id(), current, completed);
    }

    public boolean fail(Transaction current, String error) {
        Transaction failed = new Transaction(
                current.id(), current.state(), current.nonce(), current.profile(), current.expiresAt(),
                Status.FAILED, null, error);
        return transactions.replace(current.id(), current, failed);
    }

    private boolean notExpired(Transaction transaction) {
        return transaction.expiresAt().isAfter(clock.instant());
    }

    private String randomValue() {
        return UUID.randomUUID() + "." + UUID.randomUUID();
    }

    public enum Status {
        PENDING,
        VERIFIED,
        FAILED
    }

    public record Transaction(
            String id,
            String state,
            String nonce,
            CredentialProfile profile,
            Instant expiresAt,
            Status status,
            VerificationResult result,
            String error) {
    }

    public record VerificationResult(String issuer, String credentialType, Map<String, Object> claims) {
    }
}
