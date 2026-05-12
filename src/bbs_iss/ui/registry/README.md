# Registry UI

This subdirectory contains the Flask-based web interface for the **Registry** entity. The UI provides a read-only (with deletion capability) administrative view into the central storage of `IssuerPublicData` records.

## Architecture & Integration

The application is initialized via `create_registry_ui(registry: RegistryInstance, port=8001)` in `app.py`. 

Because the Registry is entirely passive—serving only as a Key-Value store that responds to external requests—there is no `Orchestrator` required. The UI mounts directly onto the `RegistryInstance` object.

### State Management (`RegistryAppState`)
The UI maintains a minimal `RegistryAppState` to track `RequestTrail` logs for transparency. Since the registry does not execute multi-step protocols itself, these logs merely record incoming `GET`, `BULK_GET`, `REGISTER`, and `UPDATE` messages.

## Endpoints & Workflows

### 1. Dashboard (`GET /`)
Renders `dashboard.html`. Provides the central administrative view:
- **Registry Records**: Iterates directly over `registry.store` (a dictionary mapping `issuer_name` to `IssuerPublicData`).
- **Record Display**: For each issuer, the UI expands to show:
  - The Issuer's Name.
  - The Public Key (hex string).
  - The Revocation Bitstring (displayed as pre-formatted text).
  - Epoch configuration parameters.
  - **Credential Schema**: The `CredentialSchema` structurally detailing what the issuer provides (Type, Context, Revealed Attributes, Hidden Attributes).
- **Protocol Trails**: Shows all incoming messages that the registry has processed.

### 2. Deletion (`POST /delete/<issuer_name>`)
Allows an administrator to forcefully prune an issuer from the registry. 
- Removes the key from the `registry.store` dictionary.
- *Note: This does not revoke existing credentials. It simply stops the registry from advertising the issuer's public data on future bulk syncs.*

## Templates & Assets
- `templates/dashboard.html`: The single-page view listing all stored issuers and logs.
- `static/style.css`: The shared terminal-aesthetic stylesheet ensuring visual consistency across the entire prototype ecosystem.
