# IntelliJ HTTP Client Requests

Start the issuer:

```bash
./mvnw spring-boot:run
```

Open `issuer.http`, select the `local` environment, and run individual requests
from the gutter.

For a complete issuance flow, run these requests in order:

1. `createOffer`
2. `getCredentialOffer` (optional)
3. `exchangePreAuthorizedCode`
4. `createNonce`
5. `issueCredential`

The response handlers retain the offer ID, pre-authorized code, access token,
and nonce for subsequent requests. The final request creates an ephemeral P-256
wallet key and signs the required `openid4vci-proof+jwt` proof.

Set `configurationId` in `http-client.env.json` to one of:

- `personal_id`
- `university_diploma`
- `drivers_license`

The scripted ES256 proof generation uses the Web Crypto API available in
IntelliJ IDEA 2026.1 and newer. It imports a demo-only P-256 private key and
places the matching public JWK in the proof header. The fixed key avoids HTTP
Client limitations around serializing and exporting generated `CryptoKey`
instances.
