# AGENTS.md

## Project Overview

This repository is a Java 25 / Spring Boot 4 demo issuer for the OpenID for
Verifiable Credential Issuance 1.0 pre-authorized code flow. It issues
`dc+sd-jwt` credentials using Nimbus JOSE JWT.

The implementation is intentionally demo-scoped. State and signing keys are
in-memory and regenerated at startup. Do not imply that the service provides
production-grade identity proofing, durable storage, key management,
revocation, TLS, DPoP, PAR, or an authorization code flow.

## Build And Run

Use the Maven wrapper:

```bash
./mvnw verify
./mvnw spring-boot:run
```

The service runs on `http://localhost:8080` by default. Configuration lives in
`src/main/resources/application.properties`.

Run a focused test with:

```bash
./mvnw -Dtest=ClassName test
```

## Code Layout

- `src/main/java/dev/vcdemo/issuer/web`: HTTP endpoints and protocol error handling.
- `src/main/java/dev/vcdemo/issuer/service`: issuance state, proof validation,
  issuer keys, and SD-JWT VC construction.
- `src/main/java/dev/vcdemo/issuer/model`: protocol DTOs and credential definitions.
- `src/main/java/dev/vcdemo/issuer/config`: Spring Security configuration.
- `src/test/java`: unit tests and the end-to-end OID4VCI issuance flow.

## Implementation Guidelines

- Preserve the existing package structure and constructor injection style.
- Prefer Java records and immutable collections for protocol data.
- Keep controllers focused on HTTP/protocol orchestration. Put cryptographic
  validation, credential construction, and state transitions in services.
- Use Nimbus JOSE JWT APIs for JOSE, JWT, JWK, signatures, and claims. Do not
  hand-build or parse security tokens with string manipulation.
- Use Jackson for JSON serialization and parsing.
- Keep protocol field names and media types aligned with OID4VCI 1.0,
  `draft-ietf-oauth-sd-jwt-vc-16`, and RFC 9901.
- Treat pre-authorized codes, access tokens, and nonces as single-use or
  time-limited security values. Changes to their lifecycle require focused
  regression tests.
- Validate wallet proofs before issuing credentials. Preserve checks for the
  JOSE type, ES256 signature, public JWK, audience, nonce, and issuance time.
- Do not expose private JWK material or sensitive token values through metadata,
  logs, or error responses.
- Keep changes within demo scope unless the task explicitly expands it.

## Testing Expectations

- Add or update tests for every protocol or security behavior change.
- Use unit tests for isolated state and SD-JWT behavior.
- Extend `IssuanceFlowIntegrationTest` when an endpoint, request/response shape,
  metadata value, or complete issuance path changes.
- Parameterize credential-flow tests across `CredentialType` when behavior
  should be shared by every supported credential.
- Run `./mvnw verify` before considering a change complete.

## Local Conventions

- Use four-space indentation in Java.
- Keep imports explicit and allow the formatter to group static imports last.
- Use descriptive protocol names rather than abbreviations that are not defined
  by the relevant specification.
- Avoid unrelated refactors and generated-file churn.
- Update `README.md` when setup instructions, endpoints, supported credential
  types, protocol versions, or documented scope change.
