# Verifiable Credential Issuer Demo

Java 25 / Spring Boot 4 demo issuer implementing the OpenID for Verifiable
Credential Issuance 1.0 pre-authorized code flow. It issues three
`dc+sd-jwt` credentials:

- `personal_id`
- `university_diploma`
- `drivers_license`

The SD-JWT VC representation follows
`draft-ietf-oauth-sd-jwt-vc-16` and RFC 9901. Demo subject claims are
selectively disclosable; issuer, type, validity, digest algorithm, and holder
key binding remain in the signed JWT.

## Run

```bash
./mvnw spring-boot:run
```

Issuer metadata:

```text
http://localhost:8080/.well-known/openid-credential-issuer
```

Create a credential offer:

```bash
curl -X POST http://localhost:8080/demo/offers/personal_id \
  -H 'Content-Type: application/json' \
  -d '{}'
```

The response contains a pre-authorized code and a retrievable credential offer.
A wallet then:

1. Exchanges the code at `POST /oauth2/token`.
2. Obtains `c_nonce` from `POST /nonce`.
3. Creates an ES256 `openid4vci-proof+jwt` containing the issuer as `aud`, the
   nonce, `iat`, and its public JWK in the JOSE header.
4. Calls `POST /credential` with the bearer token, configuration ID, and proof.

Run all unit and integration tests:

```bash
./mvnw verify
```

## Scope

This is an interoperability-focused demo, not a production issuer. State and
keys are generated in memory on startup. TLS, end-user authentication,
authorization code flow, PAR, DPoP, credential status/revocation, durable
storage, HSM-backed keys, and policy/identity proofing are intentionally out of
scope.

Specifications:

- https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-16.html
