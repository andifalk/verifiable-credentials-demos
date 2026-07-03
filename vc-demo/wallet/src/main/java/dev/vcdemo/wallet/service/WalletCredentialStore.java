package dev.vcdemo.wallet.service;

import dev.vcdemo.wallet.model.CredentialType;
import dev.vcdemo.wallet.model.WalletCredential;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class WalletCredentialStore {

    private final ConcurrentHashMap<String, WalletCredential> credentials = new ConcurrentHashMap<>();

    public void save(WalletCredential credential) {
        credentials.put(credential.id(), credential);
    }

    public Optional<WalletCredential> find(String id) {
        return Optional.ofNullable(credentials.get(id));
    }

    public Optional<WalletCredential> latest(CredentialType type) {
        return credentials.values().stream()
                .filter(credential -> credential.type() == type)
                .max(Comparator.comparing(WalletCredential::receivedAt));
    }

    public List<WalletCredential> all() {
        return credentials.values().stream()
                .sorted(Comparator.comparing(WalletCredential::receivedAt).reversed())
                .toList();
    }
}
