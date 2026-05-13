# Issuer UI

This subdirectory contains the Flask-based web interface for the **Issuer** entity. The UI is designed to sit on top of the underlying `IssuerOrchestrator` and `IssuerInstance`, providing a browser-accessible dashboard without modifying the core cryptographic logic.

## Architecture & Integration

The application is initialized via `create_issuer_ui(orch: IssuerOrchestrator, port=8002)` in `app.py`.

### Technical Implementation: Orchestrator Hooking
Since the core `IssuerInstance` is designed to be a "pure" cryptographic state machine, it does not keep a permanent log of issued credentials. To provide this functionality in the UI, we use a **Decorator Pattern** to hook the entity's `process_request` method:
```python
original_process = entity.process_request
def hooked_process(request):
    response = original_process(request)
    if isinstance(response, ForwardVCResponse):
        # UI layer intercepts the signed VC and logs it
        state.add_credential(response.credential)
    return response
entity.process_request = hooked_process
```

## Endpoints & Workflows

### 1. Dashboard (`GET /`)
- **Credential Schema**: The structural metadata defining what credentials this issuer creates.
- **Bitstring Status**: A live ASCII-art visualization of the current epoch's revocation bitstring. The UI reads the raw bitstring from the `BitstringManager` and parses it into a grid for the dashboard.
- **Auto-Refresh Logic**: The dashboard polls `/api/credentials-count` every 3 seconds. To prevent UI flickers or data loss, it only reloads if the user is not currently focused on a schema input or configuration form.

### 2. Schema Management (`POST /update-schema`)
Allows the issuer to completely redefine their `CredentialSchema`.
- **Structural Integrity**: The route enforces the BBS+ message indexing requirement. It automatically appends the hidden `LinkSecret` and revealed metadata fields (`validUntil`, `revocationMaterial`, `metaHash`) to the user's custom fields, ensuring that the resulting `IssuanceAttributes` object has the correct internal indices for cryptographic signing.

### 3. Revocation (`POST /revoke/<index>`)
- **Workflow**: When an administrator clicks "Revoke", the UI calculates the bit index from the hex-encoded `revocationMaterial`. It then calls `entity.revoke_index()`, which updates the local `BitstringManager`. 
- **Registry Synchronization**: Immediately following the local update, the UI triggers `orch.update_registry()` to ensure that the global registry reflects the revocation in real-time.

## Templates & Assets
- `templates/dashboard.html`: Single-page view using `<details>` tags for expandable JSON payloads.
- `static/style.css`: Shared terminal aesthetic with specific classes for the ASCII bitstring grid (`.bit-grid`).

