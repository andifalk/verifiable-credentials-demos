# Selective Disclosure Demo

This module demonstrates selective disclosure with verifiable credentials using a Spring Boot backend.

## Overview

- A compact demo that shows the end-to-end flow for issuing verifiable credentials with selectively-disclosable claims
  and verifying presentations derived from them.

## Key features

- Demonstrates selective disclosure and basic verification checks (example: age >= 18) using verifiable presentations.

## Contents

- `pom.xml` — Maven build for the Spring Boot application.
- `src/main/kotlin` — Application source code (controllers, services, models).
- `src/main/resources` — Application configuration and templates/static assets used by the UI.
- `src/test/kotlin` — Unit and integration tests.

## Running the demo

1. Build:

    ```bash
    mvn -f selective-disclosure-demo/ clean package -DskipTests
    ```

2. Run the service:

    ```bash
    java -jar selective-disclosure-demo/target/*.jar
    ```

3. Open the app in a browser (default port 8080) and use the UI to list available credentials, view details, and
   exercise the issuance flow.

## Troubleshooting

- Port conflicts: if another service is running on 8080, set `server.port` in `application.yml` or use
  `-Dserver.port=XXXX` when starting.
- Missing classes or unresolved references in tests: verify package structure and that classes used by tests are
  compiled and present under `src/main/kotlin`.

## Notes

- The in-memory wallet is intentionally ephemeral and only suitable for demos. For production use, replace it with a
  persistent store.
- This module is intended as an educational demo to showcase selective disclosure concepts and should not be used as-is
  in production systems.