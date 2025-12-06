# Verifiable Credentials Demos

This repository contains multiple demo applications that demonstrate Verifiable Credentials (VC) and related OpenID
flows for issuance and presentation. The demos are intentionally small, self-contained Spring Boot applications (Kotlin)
and simple static frontends to illustrate concepts and integration points.

Quick overview

- Purpose: Provide runnable examples of issuing, holding (wallet), and verifying verifiable credentials using the OpenID
  for Verifiable Credential Issuance and Presentations specs.
- Tech stack: Kotlin, Spring Boot, Thymeleaf (simple UI), Maven for build and test.
- Audience: Developers learning about VCs, proof-of-concept implementers, and educators.

Structure and modules

- `issuer/` — Issuer Spring Boot app
    - Implements credential offer endpoints and the issuance flow (callback handling, token exchange, POST
      `/credential`) following OpenID for VC Issuance patterns.
    - Exposes endpoints used by wallets to fetch available credential offers and to request credentials.
    - Useful for running a local issuer during demos and tests.

- `verifier/` — Verifier Spring Boot app
    - Demonstrates verifying verifiable presentations using OpenID for Verifiable Presentations flows.
    - Contains example verification logic (for demo scenarios such as age checks).

- `wallet/` — Wallet (holder) Spring Boot app
    - A simple holder application that stores issued credentials and can start issuance flows against the `issuer` app.
    - Includes Thymeleaf-driven UI pages: list of available offers, credential details, and a "My Credentials" page with
      persisted issued credentials (in-memory by default).
    - Implements the OAuth2 authorization code flow callback and token exchange, posts authorization to `/credential` to
      complete issuance.

- `selective-disclosure-demo/` — Selective disclosure demo module
    - Focused demo showing selective disclosure and presentation creation/verification, including UI pages with JSON
      previews of credential shapes and sample selective disclosure checks (for example, age >= 18).
    - Includes an in-memory wallet and unit tests that mock remote issuer interactions.

- `mock-eudi-wallet-demo/` — Static EUDI wallet mock frontend
    - A static, browser-based mock wallet that simulates basic wallet UI and behavior for testing and demos. Not a
      Spring app — just static HTML/JS/CSS.

What you'll find in each module

- Source: `src/main/kotlin` (Spring Boot controllers, services, models).
- Resources: `src/main/resources` (templates, static assets, `application.yml` / `application.properties`).
- Tests: `src/test/kotlin` (unit and integration tests). Many tests mock `RestTemplate` or other HTTP clients to avoid
  external dependencies.
- Build: Each module is a Maven subproject with its own `pom.xml`. The root `pom.xml` coordinates the multi-module
  build.

Quick start (local)

1. Build everything:

   mvn -T 1C -DskipTests clean package

2. Run a module (example: issuer):

   mvn -f issuer/ spring-boot:run

   Or run the packaged jar:

   java -jar issuer/target/*.jar

3. Start the `wallet` app similarly and use the UI (default port 8080) to list offers and request credentials against
   the `issuer` app.

Configuration

- Each application reads standard Spring Boot configuration from `application.yml` / `application.properties` under
  `src/main/resources`. Key configurable items include:
    - OAuth2 / Authorization Server settings used for issuance: `auth.server.url`, `auth.client.id`,
      `auth.redirect.uri` (or the module-specific property names used in each app).
    - `server.port` — change the app port to avoid conflicts.
    - Issuer URLs (credential offer endpoint, credential metadata/schema endpoints) used by wallets.

Testing

- Run module tests with Maven, for example:

  mvn -f wallet/ test

- Tests frequently mock network interactions (for example using Mockito to mock `RestTemplate`) so they can run offline.
- If you see compile-time errors in tests such as `Unresolved reference 'IssuedCredentialStore'`, check that the
  referenced class exists in `src/main/kotlin` and that package names are consistent between tests and implementation.

Notes and troubleshooting

- Ports: If two apps try to use port 8080, set `server.port` or run them one at a time.
- Persistence: Wallets in these demos often use an in-memory store for simplicity. Data will be lost when the app
  restarts.
- External dependencies: The demos assume an OAuth2 authorization server or simulated issuer for full issuance flows.
  Use the `issuer` app as a local issuer for testing.
- Security: These demos are not production hardened. They show concepts and flows only.

Contributing

- Bug fixes, documentation improvements, and small features are welcome. Open a PR against the repository and include a
  short description of your change.

License

- See the `LICENSE` file at the repository root.
