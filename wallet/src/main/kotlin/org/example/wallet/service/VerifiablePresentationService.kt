package org.example.wallet.service

import com.authlete.sd.Disclosure
import com.authlete.sd.SDJWT
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import jakarta.annotation.PostConstruct
import org.springframework.stereotype.Service
import java.text.ParseException
import java.util.UUID

const val WALLET_KEY = ("{\n"
        + "  \"kty\": \"EC\",\n"
        + "  \"alg\": \"ES256\",\n"
        + "  \"crv\": \"P-256\",\n"
        + "  \"kid\": \"_M6jQowr-8V8myJ9xtXYPmHeYjd1VegmHTxj97vtmHA\",\n"
        + "  \"x\": \"Yiij9HQqyvmSCGbq0walvnelHgIprmcJ0Ah4HzBjJqU\",\n"
        + "  \"y\": \"D9VFlhQ5ZRNp2NWJbTp0UxhmEg0rsuRcmmbj_Iqo1s0\",\n"
        + "  \"d\": \"FoV0kbTmPILo2qFU-4UokJW39e01iSUY4gmkVqzHloE\"\n"
        + "}\n")

@Service
class VerifiablePresentationService {

    private lateinit var walletKey: JWK

    @PostConstruct
    fun init() {
        // Create a wallet key, which is to be embedded in the credential
        // JWT and used for signing the key binding JWT.
        walletKey = JWK.parse(WALLET_KEY)
    }

    fun createVerifiablePresentation(incomingVc: String): String {
        // In a real implementation, you would add proof, sign the VP, etc.
        // Here we just return the VP as is for simplicity.
        val vc = SDJWT.parse(incomingVc)
        val vp = createVP(vc, walletKey) // Using the same key for simplicity
        return vp.toString()
    }

    private fun createVP(vc: SDJWT, walletKey: JWK): SDJWT {
        // Select disclosable claims to be passed to verifiers.
        // In this example, only the first one is disclosed.
        val disclosures = vc.disclosures

        // The intended audience of the verifiable presentation.
        val audience = mutableListOf("https://verifier.example.com")

        // Create a binding JWT, which is part of a verifiable presentation.
        val bindingJwt: SignedJWT =
            createBindingJwt(vc, disclosures, audience, walletKey)

        // Create a verifiable presentation in the SD-JWT format.
        return SDJWT(vc.credentialJwt, disclosures, bindingJwt.serialize())
    }

    @Throws(ParseException::class, JOSEException::class)
    private fun createBindingJwt(
        vc: SDJWT, disclosures: MutableList<Disclosure>,
        audience: MutableList<String>, signingKey: JWK
    ): SignedJWT {
        // Create the header part of a binding JWT.
        val header = createBindingJwtHeader(signingKey)

        // Create the payload part of a binding JWT.
        val payload =
            createBindingJwtPayload(vc, disclosures, audience)

        // Create a binding JWT. (not signed yet)
        val jwt = SignedJWT(header, JWTClaimsSet.parse(payload))

        // Create a signer.
        val signer = DefaultJWSSignerFactory().createJWSSigner(signingKey)

        // Let the signer sign the binding JWT.
        jwt.sign(signer)

        // Return the signed binding JWT.
        return jwt
    }

    private fun createBindingJwtHeader(signingKey: JWK): JWSHeader {
        // The signing algorithm.
        val alg = JWSAlgorithm.parse(signingKey.algorithm.name)

        // The key ID.
        val kid = signingKey.keyID

        // Prepare the header part of a binding JWT. The header represents
        // the following:
        //
        //   {
        //      "alg": "<signing-algorithm>",
        //      "kid": "<signing-key-id>",
        //      "typ": "kb+jwt"
        //   }
        //
        return JWSHeader.Builder(alg).keyID(kid)
            .type(JOSEObjectType("kb+jwt"))
            .build()
    }


    private fun createBindingJwtPayload(
        vc: SDJWT, disclosures: MutableList<Disclosure>, audience: MutableList<String>
    ): MutableMap<String, Any> {
        val payload: MutableMap<String, Any> = mutableMapOf()

        // iat
        //
        // The issuance time of the binding JWT. The SD-JWT specification
        // requires this claim.
        payload["iat"] = System.currentTimeMillis() / 1000L

        // aud
        //
        // The intended receiver of the binding JWT. The SD-JWT specification
        // requires this claim.
        payload["aud"] = audience

        // nonce
        //
        // A random value ensuring the freshness of the signature. The SD-JWT
        // specification requires this claim.
        payload["nonce"] = UUID.randomUUID().toString()

        // sd_hash
        //
        // The base64url-encoded hash value over the Issuer-signed JWT and the
        // selected disclosures. The SD-JWT specification requires this claim.
        payload["sd_hash"] = computeSdHash(vc, disclosures)

        return payload
    }

    private fun computeSdHash(vc: SDJWT, disclosures: MutableList<Disclosure>): String {
        // Compute the SD hash value using the credential JWT in the
        // verifiable credential and the disclosures in the verifiable
        // presentation (not those in the verifiable credential).
        return SDJWT(vc.credentialJwt, disclosures).sdHash
    }

}