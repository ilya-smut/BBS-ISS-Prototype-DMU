# Registry UI

This subdirectory contains the Flask-based web interface for the **Registry** entity. The UI provides an administrative view into the central storage of `IssuerPublicData` records.

## Architecture & Integration

The application is initialized via `create_registry_ui(orch: RegistryOrchestrator, port=8001)` in `app.py`. 

### Architectural Shift: Unified Orchestration
While the Registry is a passive entity (it does not initiate outbound protocol flows), it has been migrated to use a `RegistryOrchestrator`. 
- **Rationale**: This allows the Registry to follow the same bootstrap and listener patterns as the other entities. 
- **Benefit**: The orchestrator provides a standardized `RequestTrail` log, making all incoming `REGISTER`, `UPDATE`, and `GET` messages visible on the dashboard.

## Endpoints & Workflows

### 1. Dashboard (`GET /`)
- **Direct Store Inspection**: The UI iterates directly over the `orch.entity._store` dictionary to render the list of registered issuers.
- **Deep Detail**: For each issuer, the UI extracts and displays the `CredentialSchema`, the full public key, and the current state of the revocation bitstring.
- **Auto-Refresh**: The dashboard uses the 3-second polling mechanism targeting `/api/records-count` to automatically reload whenever a new issuer registers or an existing record is deleted.

### 2. Management (`POST /delete/<issuer_name>`)
- **Forceful Pruning**: Allows administrators to manually remove an issuer record. 
- **Implementation**: Deletes the key from the entity's internal `_store`. This immediately prevents any Holder or Verifier from resolving that issuer's public data in future synchronization attempts.

## Templates & Assets
- `templates/dashboard.html`: The administrative overview with auto-refresh logic.
- `static/style.css`: Shared terminal-inspired aesthetic for consistency.

