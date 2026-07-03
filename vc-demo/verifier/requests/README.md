# IntelliJ HTTP Client Requests

Start the verifier with:

```bash
./mvnw spring-boot:run
```

Select the `local` HTTP Client environment, then run requests from top to
bottom within each file:

- `metadata.http`: verifier discovery metadata.
- `presentations.http`: creates and reads transactions for every credential profile.
- `direct-post.http`: submits wallet-generated SD-JWT+KB presentations.
- `error-cases.http`: runnable validation and one-time-state failure scenarios.
- `actuator.http`: Spring Boot health and info endpoints.

Response handlers store transaction IDs and states as IntelliJ global
variables. Transactions expire after five minutes, so rerun the corresponding
create and request calls when variables become stale.

Successful direct-post verification requires a fresh presentation bound to the
authorization request's `nonce` and verifier audience. Set those values in
`http-client.env.json`; do not commit real credentials or private keys.
