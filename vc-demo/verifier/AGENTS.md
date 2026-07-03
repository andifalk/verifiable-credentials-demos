# Repository Guidelines

## Project Structure & Module Organization

This is a Java 25 / Spring Boot 4 OpenID for Verifiable Presentations verifier.

- `src/main/java/dev/vcdemo/verifier/`: application code.
- `model/`: credential profiles and protocol data models.
- `service/`: transaction storage, issuer-key resolution, and SD-JWT verification.
- `web/`: HTTP controllers and protocol error handling.
- `src/main/resources/application.properties`: local URLs, ports, and actuator settings.
- `src/test/java/`: unit and Spring MVC integration tests mirroring the main package structure.

Keep protocol validation in services, HTTP concerns in `web`, and wire-format records or enums in `model`.

## Build, Test, and Development Commands

Use the checked-in Maven wrapper:

```bash
./mvnw clean verify         # compile and run the full test suite
./mvnw test                 # run tests without packaging
./mvnw spring-boot:run      # start the verifier on port 8081
./mvnw package              # create target/vc-verifier-*.jar
```

For an end-to-end local flow, start the sibling issuer at `../issuer` on port 8080 before running this service.

## Coding Style & Naming Conventions

Use four-space indentation, same-line braces, and one public type per file. Use `UpperCamelCase` for types, `lowerCamelCase` for methods and variables, and descriptive test names such as `rejectsExpiredCredential`. Keep packages lowercase under `dev.vcdemo.verifier`.

Prefer constructor injection, immutable collections/records, and small validation methods. Preserve protocol terminology (`vp_token`, `sd_hash`, `dc+sd-jwt`) exactly at serialization boundaries. No standalone formatter or linter is configured; match surrounding code and let `./mvnw verify` be the minimum quality gate.

## Testing Guidelines

Tests use JUnit 5, AssertJ, Spring Boot Test, and MockMvc. Name test classes `*Test.java`; place service tests in the corresponding package and cross-layer flows at the application package root. Add positive and negative cases for signature, issuer, expiry, nonce, audience, disclosure, and one-time-state behavior. Generate test keys and credentials locally; avoid external network dependencies.

## Commit & Pull Request Guidelines

Git history is not available in this checkout, so no repository-specific commit format can be inferred. Use short, imperative subjects, for example `Reject duplicate disclosed claims`, and keep each commit focused.

Pull requests should explain behavior changes, identify affected endpoints or protocol checks, link relevant issues/specification sections, and report `./mvnw verify` results. Include example requests or responses when the API contract changes.

## Security & Configuration

Never commit private keys, real credentials, or production issuer URLs. Treat `application.properties` defaults as local-demo settings only; production deployments require HTTPS, durable state, revocation/status validation, and managed key material.
