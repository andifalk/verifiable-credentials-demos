# Verifiable Credential Web Wallet

Spring MVC and Thymeleaf demo wallet for the sibling issuer and verifier
applications. It runs on `http://localhost:8082` and supports:

- OID4VCI 1.0 pre-authorized code issuance
- OID4VP 1.0 DCQL and `direct_post` presentation
- `personal_id`, `university_diploma`, and `drivers_license`
- ES256 wallet proofs and SD-JWT Key Binding JWTs
- in-memory credential and private holder-key storage
- selectable disclosures
- display of the original issuer SD-JWT and submitted SD-JWT+KB presentation

## Run all applications

Use three terminals:

```bash
cd ../issuer
./mvnw spring-boot:run
```

```bash
cd ../verifier
./mvnw spring-boot:run
```

```bash
cd ../wallet
./mvnw spring-boot:run
```

Open http://localhost:8082. Issue a credential, inspect its original SD-JWT,
select disclosures, and present it to the verifier.

The verifier's current DCQL requests require all credential claims. The wallet
still allows deselection so verifier rejection can be demonstrated. The
presentation page shows the generated token containing the issuer JWT,
selected disclosures, and final `kb+jwt`.

## Validation

Before storage, the wallet validates the issuer signature through `/jwks`,
issuer and type, expiry, holder-key binding, and disclosure digests. During
presentation it validates the verifier response type, response mode, and DCQL
credential format before submitting the VP Token.

Run tests:

```bash
./mvnw verify
```

The test suite covers holder-key retention, selective disclosure, issuance
proofs, KB-JWT generation, and complete MVC issuance/presentation flows for
all three credential types.

This is not a production wallet. Credentials and private keys are lost on
restart. User authentication, encrypted storage, device key protection,
credential status, request-object signatures, response encryption, and trust
management beyond the configured issuer and verifier are out of scope.

Specifications:

- https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-16.html
