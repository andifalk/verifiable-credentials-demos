# Verifiable Credentials with Keycloak

Here you find some demos on how to use the experimental feature of Keycloak for Verifiable Credentials (Issuer and Verifier)

## Pre-Requisites

- Docker engine and docker compose
- [Developer toolkit for OpenID4VC](https://github.com/dominikschlosser/oid4vc-dev)
- [Keycloak OID4VP verifier extension](https://github.com/ba-itsys/keycloak-extension-oid4vp)

## Setup 

1.Install [Developer toolkit cli client for OpenID4VC](https://github.com/dominikschlosser/oid4vc-dev) via release download
2.Clone [Developer toolkit for OpenID4VC](https://github.com/dominikschlosser/oid4vc-dev) repository for executing the demos

## Keycloak as Issuer

This demo starts a Keycloak instance as Verifiable Credential Issuer and imports the required realm configuration and 
then interacts with Keycloak to issue a Verifiable Credential to a locally running wallet instance.

Run these steps to start the demo:

1. Open a terminal and navigate to the `oid4vc-dev/examples/keycloak-issuer-wallet` directory
2. Run `./start.sh --setup-only`. This starts Keycloak and imports the realm configuration
3. Open your browser and navigate to `http://localhost:8080/` to open the Keycloak admin console (login with admin/admin)
4. Switch to the `oidc4vc-demo` realm
5. Check the realm settings and make sure the `Verifiable Credentials` feature is enabled
6. On the `token` tab of the real settings make sure that the `Pre-Authorized Code Lifespan` is set to at least 2 minutes.
7. Verify the client scope `membership-credential` (used by the `oid4vc-demo-client`) is created and includes the `OID4VC Mapper` mappers
8. Now run script `./scripts/create-offer.sh` to get the credential offer from the Keycloak server including pre-authorized code
9. Copy the output beginning from `openid-credential-offer://` up to the end
10. Run `oid4vc-dev wallet accept [offer]` (replace "[offer]" with your copied offer from previous step) to issue the credential to the wallet
11. Run `oid4vc-dev wallet list` to see the issued credentials.
12. Run `oid4vc-dev wallet logs` to all interactions between the wallet and Keycloak
13. Run `oid4vc-dev wallet serve --port 4300` to start the wallet UI. Navigate your brosers to `http://localhost:4300/` to see the issued credential.

You may also want to look inside the credential JWT to see the claims with their ID's.
For this run `oid4vc-dev wallet list` to see the issued credentials. Then run `oid4vc-dev wallet show [id]` to show the credential details
Now run `oid4vc-dev serve --port 4200` to show a locally running decoder for the credential.
Navigate your browser to `http://localhost:4200/` and paste your credential to see the decoded credential.

After finishing the demo make sure you run `docker compose down` in the `oid4vc-dev/examples/keycloak-issuer-wallet` folder to stop the Keycloak instance.
Also clean up the wallet instance by running 
`oid4vc-dev wallet remove --all` to remove all credentials and `oid4vc-dev wallet logs clean` to clear all wallet logs.

## Keycloak as Verifier

This demo starts a Keycloak instance as Verifiable Credential Verifier (by installing the corresponding extension) and imports the required realm configuration and
then interacts with Keycloak to verify a Verifiable Credential presented by a locally running wallet instance.

1. Open a terminal and navigate to the `oid4vc-dev/examples/keycloak-verifier-oid4vpt` directory
2. Run `./start.sh`. This runs the complete demo by importing test credentials into the wallet and presenting a credential to Keyckloak as a verifier.
3. Run `oid4vc-dev wallet logs` to all interactions between the wallet and Keycloak
4. Run `oid4vc-dev wallet serve --port 4300` to start the wallet UI. Navigate your brosers to `http://localhost:4300/` to see the issued credential.

