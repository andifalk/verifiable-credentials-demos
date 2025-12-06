package org.example.sd.service

import com.authlete.sd.Disclosure
import com.authlete.sd.SDJWT
import com.authlete.sd.SDObjectBuilder
import com.fasterxml.jackson.annotation.JsonInclude
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import jakarta.annotation.PostConstruct
import org.example.sd.model.Address
import org.example.sd.model.Claims
import org.example.sd.model.Claims.BIRTH_DATE
import org.example.sd.model.Claims.FAMILY_NAME
import org.example.sd.model.Claims.GIVEN_NAME
import org.example.sd.model.Claims.IS_OVER_18
import org.example.sd.model.Country
import org.example.sd.model.DocumentType
import org.example.sd.model.IdentityCredential
import org.example.sd.model.Nationality
import org.springframework.stereotype.Service
import tools.jackson.databind.json.JsonMapper
import java.security.Key
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID

const val ISSUER_URL = "https://issuer.example.com"

private const val TIME_DIVISOR = 1000L

@Suppress("TooManyFunctions")
@Service
class SelectiveDisclosureService {
    private val log: KLogger = KotlinLogging.logger { SelectiveDisclosureService::class.simpleName }
    private lateinit var issuerKey: JWK
    private lateinit var walletKey: JWK
    private lateinit var jsonMapper: JsonMapper
    private lateinit var identityCredential: IdentityCredential
    private lateinit var undisclosedFields: MutableMap<String, Any>
    private lateinit var disclosures: MutableList<Disclosure>
    private lateinit var credentialJwt: SignedJWT
    private lateinit var sdJwt: SDJWT
    private lateinit var serializedSdJwt: String
    private lateinit var presentationSdJwt: SDJWT
    private lateinit var serializedPresentationSdJwt: String

    @PostConstruct
    fun init() {
        issuerKey =
            try {
                generateKey()
            } catch (ex: NoSuchAlgorithmException) {
                error(ex)
            }
        walletKey =
            try {
                generateKey()
            } catch (ex: NoSuchAlgorithmException) {
                error(ex)
            }
        jsonMapper =
            JsonMapper
                .builder()
                .changeDefaultPropertyInclusion {
                    it.withValueInclusion(JsonInclude.Include.NON_NULL)
                    it.withValueInclusion(JsonInclude.Include.NON_EMPTY)
                }.build()
        identityCredential = createIdentityCredential()
        undisclosedFields = undisclosedFields(identityCredential)
        disclosures = discloseFields(getIdentityCredential())
        credentialJwt = createCredentialJwt(undisclosedFields, disclosures)
        sdJwt =
            createSdJwt(
                undisclosedFields(identityCredential),
                disclosures,
            )
        serializedSdJwt = sdJwt.toString()
        presentationSdJwt = createVP(sdJwt)
        serializedPresentationSdJwt = presentationSdJwt.toString()
    }

    fun getIdentityCredential(): IdentityCredential = identityCredential

    fun getSerializedPresentationSdJwt(): String = serializedPresentationSdJwt

    fun getCredentialJwt(): SignedJWT = credentialJwt

    fun getPresentationSdJwt(): SDJWT = presentationSdJwt

    fun getPresentationCredentialDecoded(): String = decodeJwt(presentationSdJwt.credentialJwt)

    fun getPresentationBindingDecoded(): String = decodeJwt(presentationSdJwt.bindingJwt)

    private fun decodeJwt(jwt: String): String {
        val parts = jwt.split(".")
        val header = Base64.getUrlDecoder().decode(parts[0]).toString(Charsets.UTF_8)
        val payload = Base64.getUrlDecoder().decode(parts[1]).toString(Charsets.UTF_8)
        return StringBuilder()
            .apply {
                append("$header\n")
                append("$payload\n")
            }.toString()
    }

    private fun createIdentityCredential(): IdentityCredential {
        val credential =
            IdentityCredential(
                sub = UUID.randomUUID().toString(),
                givenName = "Max",
                familyName = "Mustermann",
                birthdate = "1990-01-01",
                isOver18 = true,
                nationality = Nationality.DE,
                address =
                    Address(
                        street = "Hauptstrasse 1",
                        city = "Berlin",
                        postalCode = "10115",
                        country = Country.DE,
                    ),
                documentType = DocumentType.NATIONAL_ID_CARD,
            )
        return credential
    }

    fun serialize(objectToSerialize: Any): String =
        jsonMapper
            .writerWithDefaultPrettyPrinter()
            .writeValueAsString(objectToSerialize)

    fun getUndisclosedFields(): MutableMap<String, Any> = undisclosedFields

    fun getDisclosures(): MutableList<Disclosure> = disclosures

    private fun discloseFields(credential: IdentityCredential): MutableList<Disclosure> {
        val disclosures = mutableListOf<Disclosure>()
        return disclosures.apply {
            add(Disclosure(GIVEN_NAME, credential.givenName))
            add(Disclosure(FAMILY_NAME, credential.familyName))
            add(Disclosure(BIRTH_DATE, credential.birthdate))
            add(Disclosure(IS_OVER_18, credential.isOver18))
            add(Disclosure(Claims.ADDRESS, credential.address))
            add(Disclosure(Claims.NATIONALITY, credential.nationality.name))
        }
    }

    fun undisclosedFields(credential: IdentityCredential): MutableMap<String, Any> {
        val undisclosedFields = mutableMapOf<String, Any>()
        undisclosedFields["sub"] = credential.sub
        undisclosedFields["document_type"] = credential.documentType.name
        return undisclosedFields
    }

    fun getSdjwt(): SDJWT = sdJwt

    private fun createSdJwt(
        undisclosedClaims: MutableMap<String, Any>,
        disclosures: MutableList<Disclosure>,
    ): SDJWT {
        val credentialJwt = createCredentialJwt(undisclosedClaims, disclosures)
        return SDJWT(credentialJwt.serialize(), disclosures)
    }

    fun getSerializedSdJwt(): String = serializedSdJwt

    fun base64Decode(value: String): String = Base64.getUrlDecoder().decode(value).toString(Charsets.UTF_8)

    private fun createCredentialJwt(
        claims: MutableMap<String, Any>,
        disclosableClaims: MutableList<Disclosure>,
    ): SignedJWT {
        // Create the header part of a credential JWT.
        val header: JWSHeader = createCredentialJwtHeader(issuerKey)

        // Create the payload part of a credential JWT.
        val payload: MutableMap<String, Any> =
            createCredentialJwtPayload(claims, disclosableClaims, walletKey)

        // Create a credential JWT. (not signed yet)
        val jwt = SignedJWT(header, JWTClaimsSet.parse(payload))

        // Create a signer.
        val signer = DefaultJWSSignerFactory().createJWSSigner(issuerKey)

        // Let the signer sign the credential JWT.
        jwt.sign(signer)

        // Return the signed credential JWT.
        return jwt
    }

    private fun createCredentialJwtHeader(signingKey: JWK): JWSHeader {
        // The signing algorithm.
        val alg = JWSAlgorithm.parse(signingKey.algorithm.name)

        // The key ID.
        val kid = signingKey.keyID

        return JWSHeader
            .Builder(alg)
            .keyID(kid)
            .type(JOSEObjectType("dc+sd-jwt"))
            .build()
    }

    private fun createCredentialJwtPayload(
        claims: MutableMap<String, Any>,
        disclosableClaims: MutableList<Disclosure>,
        bindingKey: JWK,
    ): MutableMap<String, Any> {
        // Create an SDObjectBuilder instance to prepare the payload part of
        // a credential JWT. "sha-256" is used as a hash algorithm to compute
        // digest values of Disclosures unless a different algorithm is
        // specified by using the SDObjectBuilder(String algorithm) constructor.
        val builder = SDObjectBuilder()

        // vct
        //
        // The type of the verifiable credential. The SD-JWT VC specification
        // requires this claim.
        builder.putClaim("vct", "$ISSUER_URL/identity_credential")

        // iss
        //
        // The identifier of the credential issuer. The SD-JWT VC specification
        // requires this claim.
        builder.putClaim("iss", ISSUER_URL)

        // Algorithm used to compute digests of Disclosures.
        // builder.putClaim("_sd_alg", "sha-256",)

        // iat
        //
        // The issuance time of the verifiable credential. This claim is optional in
        // the SD-JWT VC specification, but the HAIP specification requires this.
        builder.putClaim("iat", System.currentTimeMillis() / TIME_DIVISOR)

        // exp
        //
        // The expiration time of the verifiable credential. This claim is optional in
        // the SD-JWT VC specification.
        builder.putClaim("exp", Instant.now().plus(Duration.ofDays(1)).toEpochMilli() / TIME_DIVISOR)

        // cnf
        //
        // The binding key. This claim is optional in the SD-JWT VC specification,
        // but the HAIP specification requires this.
        builder.putClaim("cnf", buildCnfForBindingKey(bindingKey))

        // For each claim.
        for (claim in claims.entries) {
            // Add the claim.
            builder.putClaim(claim.key, claim.value)
        }

        // Put disclosable claims, if any.

        // For each disclosable claims.
        for (claim in disclosableClaims) {
            // Add the claim.
            builder.putSDClaim(claim)
        }

        // Create a Map instance that represents the payload part of a
        // credential JWT. The map contains the "_sd" array if disclosable
        // claims have been given.
        return builder.build()
    }

    private fun createVP(vc: SDJWT): SDJWT {
        // Select disclosable claims to be passed to verifiers.
        // In this example, only the first one is disclosed.
        val selectedDisclosures =
            vc.disclosures
                .stream()
                .filter { it.claimName == "is_over_18" }
                .collect(
                    java.util.stream.Collectors
                        .toCollection { mutableListOf<Disclosure>() },
                )

        // The intended audience of the verifiable presentation.
        val audience = mutableListOf("https://verifier.example.com")

        // Create a binding JWT, which is part of a verifiable presentation.
        val bindingJwt = createBindingJwt(vc, selectedDisclosures, audience, walletKey)

        // Create a verifiable presentation in the SD-JWT format.
        return SDJWT(vc.credentialJwt, selectedDisclosures, bindingJwt.serialize())
    }

    private fun createBindingJwt(
        vc: SDJWT,
        disclosures: MutableList<Disclosure>,
        audience: MutableList<String>,
        signingKey: JWK,
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
        return JWSHeader
            .Builder(alg)
            .keyID(kid)
            .type(JOSEObjectType("kb+jwt"))
            .build()
    }

    private fun createBindingJwtPayload(
        vc: SDJWT,
        disclosures: MutableList<Disclosure>,
        audience: MutableList<String>,
    ): MutableMap<String, Any> {
        val payload: MutableMap<String, Any> = mutableMapOf()

        // iat
        //
        // The issuance time of the binding JWT. The SD-JWT specification
        // requires this claim.
        payload["iat"] = System.currentTimeMillis() / TIME_DIVISOR

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

    @Suppress("NestedBlockDepth")
    fun verifyAge(): Boolean {
        var valid: Boolean

        // 1. Verify the credential JWT.
        valid = verifyCredentialJwt(presentationSdJwt, issuerKey)

        if (valid) {
            // 2. Verify the binding JWT.
            valid = verifyBindingJwt(presentationSdJwt)

            if (valid) {
                log.info { "Verifiable presentation verification succeeded." }
                presentationSdJwt.disclosures.find { it.claimName == IS_OVER_18 }?.let { disclosure ->
                    if (disclosure.claimValue as Boolean) {
                        log.info { "The holder is over 18 years old." }
                    } else {
                        log.error { "The holder is NOT over 18 years old." }
                        valid = false
                    }
                }
            } else {
                log.error { "Verifiable presentation verification failed: Binding JWT is invalid" }
                valid = false
            }
        } else {
            log.error { "Verifiable presentation verification failed: Credential JWT is invalid" }
            valid = false
        }

        return valid
    }

    private fun verifyCredentialJwt(
        vp: SDJWT,
        issuerKey: JWK,
    ): Boolean {
        var valid = true

        // Parse the credential JWT.
        val credentialJwt = SignedJWT.parse(vp.credentialJwt)
        val jwtClaimsSet = credentialJwt.getJWTClaimsSet()
        // Verify the signature of the credential JWT.
        val verified: Boolean = verifySignature(credentialJwt, issuerKey)
        if (verified) {
            log.info { "Credential JWT signature verification succeeded." }

            // There are other aspects to be verified. For example, it should
            // be confirmed that the payload contains the "iss" claim.
            // However, this example code is not intended to be exhaustive.
            val disclosureList = vp.disclosures
            if (disclosureList.isNotEmpty()) {
                log.info { "At least one disclosure in the credential JWT, as expected." }
                if (jwtClaimsSet.issuer != null && jwtClaimsSet.issuer == ISSUER_URL) {
                    log.info { "The issuer (iss) claim in the credential JWT is correct." }
                } else {
                    log.error { "The issuer (iss) claim in the credential JWT is missing or wrong." }
                    valid = false
                }
            } else {
                log.error { "No disclosures in the credential JWT." }
                valid = false
            }
        } else {
            log.error { "Credential JWT signature verification failed." }
            valid = false
        }

        return valid
    }

    private fun verifyBindingJwt(vp: SDJWT): Boolean {
        var valid = true

        // Extract the binding key from the payload of the credential JWT.
        val bindingKey: JWK = extractBindingKey(vp)

        // Parse the binding JWT.
        val bindingJwt = SignedJWT.parse(vp.getBindingJwt())

        // Verify the signature of the binding JWT.
        val verified: Boolean = verifySignature(bindingJwt, bindingKey)
        if (verified) {
            log.info { "Binding JWT signature verification succeeded." }
            val jwtClaimsSet = bindingJwt.getJWTClaimsSet()

            // Extract the value of the "sd_hash" from the binding JWT.
            val sdHash = jwtClaimsSet.getStringClaim("sd_hash")

            // The value of the "sd_hash" in the binding JWT must match
            // the actual SD hash value of the verifiable presentation.
            if (sdHash == vp.sdHash) {
                log.info { "The sd_hash in the binding JWT is correct." }
            } else {
                log.error { "The sd_hash in the binding JWT is wrong." }
                valid = false
            }
        } else {
            log.error { "Binding JWT signature verification failed." }
            valid = false
        }

        // There are other aspects to be verified. For example, the "typ"
        // parameter in the JWS header should be confirmed to be "kb+jwt".
        // However, this example code is not intended to be exhaustive.
        return valid
    }

    private fun extractBindingKey(vp: SDJWT): JWK {
        // Parse the credential JWT.
        val jwt = SignedJWT.parse(vp.credentialJwt)

        // The claims of the credential JWT.
        val claims = jwt.getJWTClaimsSet()

        // cnf
        val cnf = claims.getClaim("cnf")

        // jwk
        val jwk = (cnf as MutableMap<String, Any>)["jwk"]

        // Convert to a JWK instance.
        return JWK.parse(jwk as MutableMap<String, Any>)
    }

    private fun verifySignature(
        jwt: SignedJWT,
        verificationKey: JWK,
    ): Boolean {
        // Create a verifier.
        val verifier: JWSVerifier = createVerifier(jwt, verificationKey)

        // Verify the signature.
        return jwt.verify(verifier)
    }

    private fun createVerifier(
        jwt: SignedJWT,
        verificationKey: JWK,
    ): JWSVerifier {
        // Convert the JWK to a PublicKey.
        val key: Key? = convertToPublicKey(verificationKey)

        // Create a verifier.
        return DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), key)
    }

    private fun convertToPublicKey(jwk: JWK): PublicKey? {
        // The "kty" (key type) of the JWK.
        val keyType = jwk.keyType

        // EC
        return if (KeyType.EC == keyType) {
            jwk.toECKey().toPublicKey()
        } else if (KeyType.RSA == keyType) {
            jwk.toRSAKey().toPublicKey()
        } else if (KeyType.OKP == keyType) {
            jwk.toOctetKeyPair().toPublicKey()
        } else {
            throw JOSEException(
                "The key type '$keyType' is not supported.",
            )
        }
    }

    private fun computeSdHash(
        vc: SDJWT,
        disclosures: MutableList<Disclosure>,
    ): String {
        // Compute the SD hash value using the credential JWT in the
        // verifiable credential and the disclosures in the verifiable
        // presentation (not those in the verifiable credential).
        return SDJWT(vc.credentialJwt, disclosures).sdHash
    }

    private fun buildCnfForBindingKey(bindingKey: JWK): MutableMap<String, Any> {
        // Embed the key as the value of the "jwk" property.
        return mutableMapOf("jwk" to bindingKey.toPublicJWK().toJSONObject())
    }

    private fun generateKey(): ECKey {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)
        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = keyPair.public as ECPublicKey
        val privateKey = keyPair.private as ECPrivateKey
        return ECKey
            .Builder(Curve.P_256, publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .algorithm(JWSAlgorithm.ES256)
            .keyUse(KeyUse.SIGNATURE)
            .build()
    }
}
