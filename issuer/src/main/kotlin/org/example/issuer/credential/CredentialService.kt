package org.example.issuer.credential

import com.authlete.sd.Disclosure
import com.authlete.sd.SDJWT
import com.authlete.sd.SDObjectBuilder
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KLogger
import io.github.oshai.kotlinlogging.KotlinLogging
import jakarta.annotation.PostConstruct
import org.example.issuer.common.IssuerConsts.BASE_URL
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.stereotype.Service
import tools.jackson.core.type.TypeReference
import tools.jackson.databind.json.JsonMapper
import java.net.URLDecoder

const val WALLET_KEY = (
    "{\n" +
        "  \"kty\": \"EC\",\n" +
        "  \"alg\": \"ES256\",\n" +
        "  \"crv\": \"P-256\",\n" +
        "  \"kid\": \"_M6jQowr-8V8myJ9xtXYPmHeYjd1VegmHTxj97vtmHA\",\n" +
        "  \"x\": \"Yiij9HQqyvmSCGbq0walvnelHgIprmcJ0Ah4HzBjJqU\",\n" +
        "  \"y\": \"D9VFlhQ5ZRNp2NWJbTp0UxhmEg0rsuRcmmbj_Iqo1s0\",\n" +
        "  \"d\": \"FoV0kbTmPILo2qFU-4UokJW39e01iSUY4gmkVqzHloE\"\n" +
        "}\n"
)

@Service
class CredentialService(
    private val rsaKey: RSAKey,
    private val jsonMapper: JsonMapper,
) {
    private val log: KLogger = KotlinLogging.logger { CredentialService::class.simpleName }
    private lateinit var walletKey: JWK

    @PostConstruct
    fun init() {
        // Create a wallet key, which is to be embedded in the credential
        // JWT and used for signing the key binding JWT.

        // In production this should be loaded from a public wallet JWKS endpoint
        walletKey = JWK.parse(WALLET_KEY)
    }

    fun issueCredential(
        jwt: Jwt,
        request: CredentialRequest,
    ): String {
        // Dummy subject — extract from access token in production
        val subject = jwt.subject
        var credentialId: String? = null
        if (jwt.hasClaim("authorization_details")) {
            val detailsString = URLDecoder.decode(jwt.getClaim("authorization_details"), "UTF-8")

            val authorizationDetails =
                jsonMapper.readValue(detailsString, object : TypeReference<List<AuthorizationDetail>>() {})

            credentialId = authorizationDetails.getOrNull(0)?.credentialConfigurationId
        }

        if (credentialId == null) {
            if (request.credentialIdentifier != null) {
                credentialId = request.credentialIdentifier
            } else {
                error("Credential identifier is not set")
            }
        }

        // 1. Define the VC payload
        val vcClaims =
            mutableMapOf(
                "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                "type" to listOf("VerifiableCredential", credentialId),
                "sub" to subject,
            )
        val credentials = buildCredentialSubject(credentialId, subject)

        log.info { "Credentials $credentials" }

        val disclosureList =
            credentials
                .map {
                    Disclosure(it.key, it.value)
                }.toMutableList()

        log.info { "Disclosures $disclosureList" }
        disclosureList.stream().map {
            log.info { "Disclosure [salt=${it.salt},claim=${it.claimName}, claimValue=${it.claimValue}, sd=${it.digest()}]" }
        }

        val credentialJwt = createCredentialJwt(vcClaims, disclosureList, rsaKey, walletKey)

        log.info { "Credential JWT $credentialJwt" }

        return SDJWT(credentialJwt.serialize(), disclosureList).toString()
    }

    private fun buildCredentialSubject(
        identifier: String,
        subject: String,
    ): Map<String, Any> =
        when (identifier) {
            "UniversityDegreeCredential" -> {
                mapOf(
                    "id" to subject,
                    "name" to "Alice Schmidt",
                    "degree" to
                        mapOf(
                            "type" to "BachelorDegree",
                            "name" to "Bachelor of Science in Computer Science",
                            "university" to "TU Munich",
                            "awarded" to "2020-07-15",
                        ),
                )
            }

            "DigitalIDCredential" -> {
                mapOf(
                    "id" to subject,
                    "given_name" to "Alice",
                    "family_name" to "Schmidt",
                    "birthdate" to "1995-05-23",
                    "over18" to true,
                    "nationality" to "DE",
                    "document_type" to "national_id_card",
                )
            }

            "BankAccountCredential" -> {
                mapOf(
                    "id" to subject,
                    "account_holder" to "Alice Schmidt",
                    "iban" to "DE89370400440532013000",
                    "bic" to "COBADEFFXXX",
                    "bank" to "Commerzbank",
                    "account_type" to "checking",
                )
            }

            "DriversLicenseCredential" -> {
                mapOf(
                    "id" to subject,
                    "account_holder" to "Alice Schmidt",
                    "issued_at" to "2015-07-12",
                    "bic" to "COBADEFFXXX",
                    "bank" to "Commerzbank",
                    "account_type" to "checking",
                )
            }

            else -> {
                throw IllegalArgumentException("Unsupported credential type: $identifier")
            }
        }

    private fun createCredentialJwt(
        claims: MutableMap<String, Any>,
        disclosableClaims: MutableList<Disclosure>,
        signingKey: JWK,
        bindingKey: JWK,
    ): SignedJWT {
        // Create the header part of a credential JWT.
        val header: JWSHeader = createCredentialJwtHeader(signingKey)

        // Create the payload part of a credential JWT.
        val payload: MutableMap<String, Any> =
            createCredentialJwtPayload(claims, disclosableClaims, bindingKey)

        // Create a credential JWT. (not signed yet)
        val jwt = SignedJWT(header, JWTClaimsSet.parse(payload))

        // Create a signer.
        val signer = DefaultJWSSignerFactory().createJWSSigner(signingKey)

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

        // Prepare the header part of a credential JWT. The header represents
        // the following:
        //
        //   {
        //      "alg": "<signing-algorithm>",
        //      "kid": "<signing-key-id>",
        //      "typ": "dc+sd-jwt"
        //   }
        //
        // Note that the media type of SD-JWT has been changed from
        // "application/vc+sd-jwt" to "application/dc+sd-jwt". For more details,
        // please refer to the following.
        //
        //   https://datatracker.ietf.org/meeting/121/materials/slides-121-oauth-sessb-sd-jwt-and-sd-jwt-vc-02#page=51
        //   https://github.com/oauth-wg/oauth-sd-jwt-vc/pull/268
        //
        return JWSHeader
            .Builder(alg)
            .keyID(kid)
            .type(JOSEObjectType("dc+sd-jwt"))
            .build()
    }

    @Suppress("MagicNumber")
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
        builder.putClaim("vct", "https://credentials.example.com/identity_credential")

        // iss
        //
        // The identifier of the credential issuer. The SD-JWT VC specification
        // requires this claim.
        builder.putClaim("iss", BASE_URL)

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
}
