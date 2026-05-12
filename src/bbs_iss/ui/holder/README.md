# Holder UI

This subdirectory contains the Flask-based web interface for the **Holder** entity. It serves as the "user wallet" where credentials can be requested, stored, viewed, and renewed.

## Architecture & Integration

The application is initialized via `create_holder_ui(orch: HolderOrchestrator, port=8004)` in `app.py`.

Unlike the Issuer, the Holder UI does not need to heavily intercept orchestrator events, as the `HolderInstance` naturally stores credentials in its own `entity.credentials` dictionary. The UI reads directly from this dictionary to render the wallet.

### State Management (`HolderAppState`)
Maintains a reference to the orchestrator and keeps a localized list of `RequestTrail` logs to display protocol execution trails to the user.

## Endpoints & Workflows

### 1. Dashboard / Wallet (`GET /`)
Renders `dashboard.html`, serving as the primary wallet interface.
- **My Credentials**: Iterates through `entity.credentials` and displays all held credentials.
  - Dynamically calculates the current validity state (Valid, Expired, or Revoked). 
  - Revocation is checked locally by referencing the Issuer's bitstring from the `PublicDataCache`.
- **Renewal Mechanism**: If a credential is valid but its `validUntil` timestamp falls within the issuer's advertised re-issuance window, a "Renew Credential" button appears, linking to the `/reissue` route.
- **Known Issuers**: Displays a list of all issuers stored in the local cache, alongside their configured parameters and `CredentialSchema`. 

### 2. Registry Synchronization (`POST /sync-registry`)
Triggers a bulk fetch from the central registry, repopulating the local `PublicDataCache` with the latest issuer public keys, revocation bitstrings, and schemas.

### 3. Schema-Driven Issuance (`GET /issue`, `POST /issue`)
The credential request workflow strictly enforces schema compliance.
- **`GET /issue`**: The route extracts the cached schemas for all known issuers and serializes them to JSON via Jinja (`ISSUER_SCHEMAS`). 
- **Dynamic JavaScript Forms**: In `issue.html`, when the user selects an Issuer from the dropdown, `onIssuerChange()` parses the embedded JSON schema. It dynamically generates form input rows for exactly the revealed attribute keys defined in the schema, making the keys themselves read-only.
- **`POST /issue`**: Collects the submitted values. Metadata fields (`validUntil`, `revocationMaterial`, `metaHash`) are automatically excluded from the UI inputs because `IssuanceAttributes.build_commitment_append_meta()` appends them internally. The route auto-generates the `LinkSecret` hidden attribute and executes the blind-issuance protocol via `state.orch.execute_issuance()`.

### 4. Re-issuance (`POST /reissue`)
Triggered from the dashboard when a credential nears expiration. 
- Automatically creates a new `IssuanceAttributes` object, porting over all attribute values from the old credential, while generating a fresh `LinkSecret`.
- Executes `orch.execute_re_issuance()`, generating a VP of the old credential and a new commitment simultaneously.

## Templates & Assets
- `templates/dashboard.html`: The wallet view.
- `templates/issue.html`: The dynamic, schema-driven issuance request form.
- `static/style.css`: Terminal aesthetic styling, including specific visual treatments for locked schema keys (`.attr-key-locked`) and schema metadata banners.
