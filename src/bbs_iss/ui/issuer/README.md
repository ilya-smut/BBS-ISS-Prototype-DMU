# Issuer UI

This subdirectory contains the Flask-based web interface for the **Issuer** entity. The UI is designed to sit on top of the underlying `IssuerOrchestrator` and `IssuerInstance`, providing a browser-accessible dashboard without modifying the core cryptographic logic.

## Architecture & Integration

The application is initialized via `create_issuer_ui(orch: IssuerOrchestrator, port=8002)` in `app.py`.

### State Management (`IssuerAppState`)
Since Flask routes handle stateless HTTP requests but the underlying protocol is stateful, the UI maintains an `IssuerAppState` object that holds a reference to the orchestrator. It also tracks:
- `trails`: A list of `RequestTrail` objects showing protocol execution logs.
- `issued_credentials`: A list of `IssuedCredentialRecord` objects representing every credential this issuer has signed.

### Orchestrator Hooking
To track issued credentials without deeply coupling the UI to the `IssuerInstance`, the `create_issuer_ui` function implements a **decorator hook** around the entity's `process_request` method. 
If the underlying entity returns a `ForwardVCResponse`, the UI intercepts it, extracts the credential subject, and logs it to `issued_credentials` before passing it back to the orchestrator.

## Endpoints & Workflows

### 1. Dashboard (`GET /`)
Renders `dashboard.html`. Provides an overview of:
- **Configuration**: Current epoch size, re-issuance window, baseline date, and public key.
- **Credential Schema**: The structural metadata defining what credentials this issuer creates.
- **Bitstring Status**: A live ASCII-art visualization of the current epoch's revocation bitstring.
- **Issued Credentials**: Expandable records of all issued credentials showing validity, expiration, and revocation status.
- **Protocol Trails**: Diagnostic logs for executed workflows.

### 2. Configuration & Registry
- `POST /configure`: Updates the entity's configuration parameters (epoch size, baseline date, etc.).
- `POST /register` & `POST /update-registry`: Triggers the orchestrator to broadcast the issuer's current `IssuerPublicData` (including its public key, bitstring, and schema) to the central registry.

### 3. Schema Management (`POST /update-schema`)
Allows the issuer to completely redefine their `CredentialSchema`.
- Takes a schema `type`, `context`, and an ordered list of custom revealed attribute keys.
- **Automatic Handling**: The route automatically enforces BBS+ ordering rules. It appends the required BBS+ metadata fields (`validUntil`, `revocationMaterial`, `metaHash`) to the end of the revealed attributes list, and automatically manages the hidden `LinkSecret` attribute.
- Once submitted, it creates a new `CredentialSchema` object and injects it into the `IssuerInstance`. The issuer should then click "Update Registry" to broadcast this new schema to Holders.

### 4. Revocation (`POST /revoke/<index>`)
When an administrator clicks "Revoke" on an issued credential, this route:
1. Calculates the specific bit index from the credential's `revocationMaterial` hex.
2. Calls `entity.revoke_index()` to flip the bit in the `BitstringManager`.
3. Automatically triggers a registry update (`orch.update_registry()`) so that Verifiers and Holders immediately see the revoked status.

## Templates & Assets
- `templates/dashboard.html`: The single-page dashboard utilizing HTML5 `<details>` tags for expandable rows.
- `static/style.css`: A terminal-inspired dark-mode stylesheet shared stylistically across all entities. Includes specific CSS classes (`.schema-editor`, `.attr-row`) for the dynamic schema builder.
