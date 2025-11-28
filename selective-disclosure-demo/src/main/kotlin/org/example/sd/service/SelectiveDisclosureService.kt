package org.example.sd.service

import com.authlete.sd.Disclosure
import com.authlete.sd.SDJWT
import com.authlete.sd.SDObjectBuilder
import com.fasterxml.jackson.annotation.JsonInclude
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import jakarta.annotation.PostConstruct
import org.example.sd.model.DocumentType
import org.example.sd.model.IdentityCredential
import org.example.sd.model.Nationality
import org.springframework.stereotype.Service
import tools.jackson.databind.json.JsonMapper
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.UUID

const val ISSUER_URL = "https://issuer.example.com"

@Service
class SelectiveDisclosureService() {
    private lateinit var issuerKey: JWK
    private lateinit var walletKey: JWK
    private lateinit var jsonMapper: JsonMapper

    @PostConstruct
    fun init() {
        issuerKey= try {
            generateKey()
        } catch (ex: NoSuchAlgorithmException) {
            error(ex)
        }
        walletKey= try {
            generateKey()
        } catch (ex: NoSuchAlgorithmException) {
            error(ex)
        }
        jsonMapper = JsonMapper.builder().changeDefaultPropertyInclusion {
            it.withValueInclusion(JsonInclude.Include.NON_NULL)
            it.withValueInclusion(JsonInclude.Include.NON_EMPTY)
        }.build()
    }

    fun createIdentityCredential(): IdentityCredential {
        val credential = IdentityCredential(
            id = "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
            givenName = "John",
            familyName = "Doe",
            birthdate = "1990-01-01",
            isOver18 = true,
            nationality = Nationality.DE,
            documentType = DocumentType.NATIONAL_ID_CARD,)
        return credential
    }

    fun serialize(objectToSerialize: Any): String {
        return jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(objectToSerialize)
    }

    fun discloseFields(credential: IdentityCredential): MutableList<Disclosure> {
        val disclosures = mutableListOf<Disclosure>()
        disclosures.add(Disclosure("given_name", credential.givenName))
        disclosures.add(Disclosure("family_name", credential.familyName))
        disclosures.add(Disclosure("birth_date", credential.birthdate))
        disclosures.add(Disclosure("is_over_18", credential.isOver18))
        disclosures.add(Disclosure("nationality", credential.nationality.name))
        return disclosures
    }

    fun undisclosedFields(credential: IdentityCredential): MutableMap<String, Any> {
        val undisclosedFields = mutableMapOf<String, Any>()
        undisclosedFields["id"] = credential.id
        undisclosedFields["document_type"] = credential.documentType.name
        return undisclosedFields
    }

    fun createSdJwt(undisclosedClaims: MutableMap<String,Any>, disclosures: MutableList<Disclosure>,): SDJWT {
        val credentialJwt = createCredentialJwt(undisclosedClaims, disclosures)
        return SDJWT(credentialJwt.serialize(), disclosures)
    }

    fun serializeSdJwt(sdJwt: SDJWT): String {
        return sdJwt.toString()
    }

    fun createCredentialJwt(
        claims: MutableMap<String, Any>, disclosableClaims: MutableList<Disclosure>,
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

        return JWSHeader.Builder(alg).keyID(kid)
            .type(JOSEObjectType("dc+sd-jwt"))
            .build()
    }

    private fun createCredentialJwtPayload(
        claims: MutableMap<String, Any>, disclosableClaims: MutableList<Disclosure>, bindingKey: JWK
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

        // iat
        //
        // The issuance time of the verifiable credential. This claim is optional in
        // the SD-JWT VC specification, but the HAIP specification requires this.
        builder.putClaim("iat", System.currentTimeMillis() / 1000L)

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