# Verifiable Credential Demos

- `issuer/`: OID4VCI 1.0 issuer for three SD-JWT VC credential types
- `verifier/`: OID4VP 1.0 verifier that accepts presentations of those credentials
- `wallet/`: Spring MVC and Thymeleaf wallet for issuance, storage, selective
  disclosure, and presentation

Both applications require Java 25 and include independent Maven Wrappers.
Run the issuer on port 8080, verifier on port 8081, and wallet on port 8082.
