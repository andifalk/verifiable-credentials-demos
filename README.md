# Verifiable Credentials Demos

This repository contains multiple demo applications that demonstrate Verifiable Credentials (VC) and related OpenID
flows for issuance and presentation. The demos are intentionally small, self-contained Spring Boot applications (Kotlin)
and simple static frontends to illustrate concepts and integration points.

## Quick overview

- Purpose: Provide runnable examples of issuing, holding (wallet), and verifying verifiable credentials using the OpenID
  for Verifiable Credential Issuance and Presentations specs.
- Tech stack: Java, Kotlin, Spring Boot, Thymeleaf (simple UI), Maven for build and test.
- Audience: Architects & developers learning about VCs.

## Structure and modules

### VC-Demo

A complete demo with issuer, wallet, and verifier

- `issuer/` — Issuer Java Spring Boot app
   - Implements credential offer endpoints and the issuance flow (callback handling, token exchange, POST
      `/credential`) following OpenID for VC Issuance patterns.
   - Exposes endpoints used by wallets to fetch available credential offers and to request credentials.
   - Useful for running a local issuer during demos and tests.

- `verifier/` — Verifier Java Spring Boot app
    - Demonstrates verifying verifiable presentations using OpenID for Verifiable Presentations flows.
    - Contains example verification logic (for demo scenarios such as age checks).

- `wallet/` — Wallet (holder) Java Spring Boot app
    - A simple holder application that stores issued credentials and can start issuance flows against the `issuer` app.
    - Includes Thymeleaf-driven UI pages: List of available offers, credential details, and a "My Credentials" page with
      persisted issued credentials (in-memory by default).
    - Implements the OAuth2 authorization code flow callback and token exchange, posts authorization to `/credential` to
      complete issuance.

### selective-disclosure-demo 

Selective disclosure demo module
- Focused demo showing selective disclosure and presentation creation/verification, including UI pages with JSON
      previews of credential shapes and sample selective disclosure checks (for example, age >= 18).
- Includes an in-memory wallet and unit tests that mock remote issuer interactions.

### mock-eudi-wallet-demo 
Static EUDI wallet mock frontend
- A static, browser-based mock wallet that simulates basic wallet UI and behavior for testing and demos. Not a
      Spring app — just static HTML/JS/CSS.

## Keycloak integration
Demos with Keycloak as VC issuer

See [Keycloak-demo](keycloak-demos/README.md) for instructions on how to set up a Keycloak
server and configure the demos to use it.

## Notes and troubleshooting

- Ports: If two apps try to use port 8080, set `server.port` or run them one at a time.
- Persistence: Wallets in these demos often use an in-memory store for simplicity. Data will be lost when the app
  restarts.
- Security: These demos are not production hardened. They show concepts and flows only.

## Contributing

- Bug fixes, documentation improvements, and small features are welcome. Open a PR against the repository and include a
  short description of your change.

## License

- See the `LICENSE` file at the repository root.
