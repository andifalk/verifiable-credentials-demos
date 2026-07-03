# Verifiable Presentation Verifier Demo

Java 25 / Spring Boot 4 verifier implementing OpenID for Verifiable
Presentations 1.0 for the sibling issuer application. It requests and verifies
the issuer's `personal_id`, `university_diploma`, and `drivers_license`
credentials in `dc+sd-jwt` format.

The implementation uses DCQL, `response_type=vp_token`, and
`response_mode=direct_post`. It validates:

- trusted issuer and ES256 issuer signature through the issuer JWKS
- credential validity and expected `vct`
- SHA-256 selective-disclosure digests and required disclosed claims
- ES256 Key Binding JWT signature using the credential's `cnf.jwk`
- transaction `nonce`, verifier audience, `iat`, and `sd_hash`
- one-time `state` use

## Run

Start the issuer first:

```bash
cd ../issuer
./mvnw spring-boot:run
```

Then start the verifier on port 8081:

```bash
cd ../verifier
./mvnw spring-boot:run
```

Create a presentation request:

```bash
curl -X POST http://localhost:8081/api/presentations/personal_id
```

The response contains an `openid4vp://` authorization request URI and a
transaction ID. A wallet can retrieve the decoded request from
`GET /api/presentations/{transactionId}/request`, construct an SD-JWT+KB
presentation, and submit the OID4VP response as an UTF-8 form:

```text
POST /oid4vp/response
Content-Type: application/x-www-form-urlencoded

state=...&vp_token={"personal_id":["<SD-JWT+KB>"]}
```

Poll `GET /api/presentations/{transactionId}` for the verified disclosed
claims.

## Test

```bash
./mvnw verify
```

This is a demo. Transactions are in memory, HTTP is used locally, issuer trust
is configured statically, and encrypted responses, signed request objects,
verifier attestations, status/revocation, and production key management are
out of scope.

Specification:

- https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
