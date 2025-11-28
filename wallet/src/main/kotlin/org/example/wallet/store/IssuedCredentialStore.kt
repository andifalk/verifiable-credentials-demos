package org.example.wallet.store

import org.springframework.stereotype.Service
import java.util.concurrent.CopyOnWriteArrayList

@Service
class IssuedCredentialStore {
    private val credentials = CopyOnWriteArrayList<String>()

    fun add(credential: String) {
        credentials.add(credential)
    }

    fun getAll(): List<String> = credentials.toList()

    fun clear() {
        credentials.clear()
    }
}

