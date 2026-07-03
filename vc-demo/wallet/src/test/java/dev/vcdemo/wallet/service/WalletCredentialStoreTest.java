package dev.vcdemo.wallet.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import dev.vcdemo.wallet.model.CredentialType;
import dev.vcdemo.wallet.model.WalletCredential;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class WalletCredentialStoreTest {

    @Test
    void storesCredentialWithoutExposingOrLosingHolderKey() throws Exception {
        WalletCredentialStore store = new WalletCredentialStore();
        WalletCredential credential = new WalletCredential(
                "credential-1",
                CredentialType.PERSONAL_ID,
                "https://issuer.example",
                "issuer.jwt~disclosure~",
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate(),
                List.of(),
                Instant.now());

        store.save(credential);

        assertThat(store.find("credential-1")).containsSame(credential);
        assertThat(store.latest(CredentialType.PERSONAL_ID)).containsSame(credential);
    }
}
