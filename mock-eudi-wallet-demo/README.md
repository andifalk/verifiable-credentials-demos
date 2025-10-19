# Mock EUDI Wallet – SD-JWT-Visualisierung + Trust Triangle (mit Spezifikationen)

Dieses Paket ergänzt das Trust-Triangle um **Spezifikationslabels**:
- **OID4VCI** für die *Issuance*-Kante (Issuer → Holder)
- **OIDC4VP** für die *Presentation*-Kante (Holder → Verifier)
- **SD‑JWT (RFC 9421)** für selektive Offenlegung entlang der Presentation
- Optionaler Rückkanal „**Status List / Revocation**“ (Verifier → Issuer)

Alle anderen Features bleiben identisch: QR-Flow (simuliert), zwei Verifier-Anfragen (Alter ≥ 18, Wohnsitz EU), zweites Credential (Hochschulabschluss), SD-JWT-Visualisierung (🔓/🔒).

## Nutzung
1. `index.html` im Browser öffnen – oben das Trust Triangle mit Labels betrachten.
2. Unter **Issuer** Credentials ausstellen.
3. In der **Wallet** Checkboxen toggeln – SD-JWT-Chips aktualisieren sich live.
4. **Vorschau Präsentation** → JSON mit `disclosed` + `blinded`.
5. **QR** oder **Direkt prüfen** beim Verifier testen.

## Lizenz
CC-BY 4.0
