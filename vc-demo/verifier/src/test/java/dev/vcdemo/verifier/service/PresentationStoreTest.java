package dev.vcdemo.verifier.service;

import dev.vcdemo.verifier.model.CredentialProfile;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PresentationStoreTest {

    private final PresentationStore store = new PresentationStore();

    @Test
    void completedStateCannotBeUsedAgain() {
        PresentationStore.Transaction transaction = store.create(CredentialProfile.PERSONAL_ID);
        PresentationStore.VerificationResult result = new PresentationStore.VerificationResult(
                "https://issuer.example", "personal_id", Map.of("given_name", "Erika"));

        assertThat(store.findPendingByState(transaction.state())).contains(transaction);
        assertThat(store.complete(transaction, result)).isTrue();
        assertThat(store.findPendingByState(transaction.state())).isEmpty();
        assertThat(store.complete(transaction, result)).isFalse();
    }
}
