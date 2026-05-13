# Holder UI

This subdirectory contains the Flask-based web interface for the **Holder** entity. It serves as the "user wallet" where credentials can be requested, stored, viewed, and renewed.

## Architecture & Integration

The application is initialized via `create_holder_ui(orch: HolderOrchestrator, port=8004)` in `app.py`. 

### Logic Specifics: Two-Phase Presentation
The Holder UI implements a manual consent checkpoint for the Presentation protocol. This is decoupled into two phases:
1. **Request Queueing**: When the Verifier sends a `VPRequest` over HTTP, the Holder's `FlaskListener` (on port 5004) intercepts it. Because it is a `VP_REQUEST`, the listener delegates to the `HolderOrchestrator`, which appends it to a `pending_requests` list.
2. **Asynchronous Notification**: The UI's short-polling mechanism (3s) detects the addition to the list and refreshes the dashboard.
3. **Consent & Execution**: When the user clicks "Present", the UI gathers the selected `vc_name` and the `vp_request` object and calls `orch.execute_presentation()`, which computes the ZKP and POSTs the response back to the Verifier.

## Endpoints & Workflows

### 1. Dashboard / Wallet (`GET /`)
- **My Credentials**: Iterates through `entity.credentials`.
- **Validity Check Logic**: The UI calculates validity by checking the `validUntil` field against `datetime.now(timezone.utc)`.
- **Revocation Check Logic**: The UI looks up the issuer's public data in the `PublicDataCache`. It retrieves the bitstring and performs a bitwise check on the index stored in the credential's `revocationMaterial`.

### 2. Presentation Consent (`GET /present/<request_id>`)
This page provides **User Transparency**. 
- **Implementation Detail**: The route retrieves the specific `VPRequest` from the orchestrator's queue. It then scans the Holder's wallet for a credential matching the requested issuer. 
- **Internal Data Disclosure**: To help the user make an informed decision, the template extracts the actual values from the `credential_subject` dictionary of the *local* credential. This allows the user to see the private values that will be disclosed (or used to generate the ZKP) before the protocol proceeds.

### 3. Schema-Driven Issuance (`GET /issue`, `POST /issue`)
The issuance workflow uses dynamic JavaScript to enforce schema compliance.
- **Dynamic JS Injection**: The backend serializes all cached `CredentialSchema` objects into a global `ISSUER_SCHEMAS` constant in the HTML.
- **DOM Manipulation**: When the user changes the issuer dropdown, `onIssuerChange()` clears the attribute container and reconstructs it. It maps the schema's `revealed_attributes` keys to locked input labels, ensuring the user only provides values for the keys the issuer expects.

## Templates & Assets
- `templates/dashboard.html`: Wallet view with 3s auto-refresh polling.
- `templates/present.html`: Two-column consent view (Requested Fields vs. Internal Values).
- `templates/issue.html`: Dynamic schema-aware form.

