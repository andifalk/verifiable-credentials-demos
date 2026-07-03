package dev.vcdemo.issuer.service;

import dev.vcdemo.issuer.model.CredentialType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IssuanceStoreTest {

    private final IssuanceStore store = new IssuanceStore();

    @Test
    void preAuthorizedCodeCanOnlyBeExchangedOnce() {
        IssuanceStore.CreatedOffer offer = store.createOffer(CredentialType.PERSONAL_ID, null);

        assertThat(store.exchangeCode(offer.code())).isPresent();
        assertThat(store.exchangeCode(offer.code())).isEmpty();
    }

    @Test
    void nonceCanOnlyBeConsumedOnce() {
        String nonce = store.createNonce();

        assertThat(store.consumeNonce(nonce)).isTrue();
        assertThat(store.consumeNonce(nonce)).isFalse();
    }
}
