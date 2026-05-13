# UI — Browser-Based Interface

This package provides lightweight, browser-based Flask applications for interacting with the core protocol entities. These interfaces are designed to demonstrate the end-to-end functionality of the BBS-ISS prototype without requiring command-line intervention.

## Architecture

The UI layer runs on independent Flask servers (each on its own port) and hooks into the underlying orchestrator/entity classes.

```
ui/
├── holder/      # Port 8004
├── issuer/      # Port 8002
├── verifier/    # Port 8003
└── registry/    # Port 8001
```

---

## 1. Issuer UI (`issuer/app.py` & port 8002)

Provides an interface for configuring the Issuer entity, managing its credential schema, tracking issued credentials, and handling revocations.

### Key Features
- **Configuration Panel**: Set issuer name, epoch sizes, and re-issuance windows. Includes buttons to trigger registration or updates with the central Registry.
- **Credential Schema Management**:
  - Displays the currently active `CredentialSchema` (type, context, and structural ordering of revealed/hidden attributes).
  - Provides a dynamic schema editor to define a new credential structure. Revealed attribute keys are defined by the user, while metadata fields (`validUntil`, `revocationMaterial`, `metaHash`) and hidden fields (`LinkSecret`) are handled and appended automatically.
- **Issued Credentials**: A list of all credentials issued by this entity, with visual indicators for validity state (`VALID`, `EXPIRED`, `REVOKED`).
- **Revocation**: A button on each valid credential triggers a bitstring revocation, automatically synchronizing the new bitstring state with the Registry.

---

## 2. Holder UI (`holder/app.py` & port 8004)

Provides the end-user interface for requesting new credentials, managing a local credential wallet, reviewing incoming presentation requests, and tracking known issuers.

### Key Features
- **Credential Storage (Wallet)**: Lists all held credentials with their expiration and revocation status (inferred via cached issuer public data). If a credential is valid but within the re-issuance window, a "Renew" button appears to trigger the zero-knowledge re-issuance protocol.
- **Pending Presentation Requests**: Displays incoming `VPRequest` messages from Verifiers. The dashboard auto-refreshes (3-second polling) to detect new requests. Each request shows the requested fields and provides "Review & Present" and "Decline" actions.
- **Presentation Consent Flow**: When reviewing a request, the Holder sees the requested fields and can select a credential to present. Compatibility is checked: if the credential contains all requested fields, presentation can proceed; otherwise, a warning indicates the missing fields. Approving triggers the second phase of the VP protocol, sending a `ForwardVPResponse` to the Verifier.
- **Known Issuers (Cache)**: Displays the local `PublicDataCache` containing details for each known issuer, including their advertised `CredentialSchema` and revocation bitstring. Includes a "Sync Registry" button to proactively fetch all issuer data.
- **Schema-Driven Issuance Form**: 
  - An interactive form to initiate an issuance request.
  - When an Issuer is selected from the dropdown, the form dynamically reconstructs itself using the Issuer's `CredentialSchema` found in the local cache. 
  - Only the schema-defined revealed attribute keys are presented as read-only labels for the user to fill with values. Metadata fields and `LinkSecret` are handled seamlessly in the background.

---

## 3. Verifier UI (`verifier/app.py` & port 8003)

Provides an interface for requesting verifiable presentations from Holders and inspecting verification results with detailed cryptographic and policy-level checks.

### Key Features
- **Known Issuers (Cache)**: Same pattern as Holder — displays cached issuer data with a "Sync Registry" button. Required before requesting presentations so the Verifier knows which issuers exist and what fields they support.
- **Presentation Request Form**:
  - Select an issuer from the cache to load its `CredentialSchema`.
  - Schema fields appear as checkboxes; the user selects which fields to request disclosure of.
  - Special hints indicate that `validUntil` enables expiration checks and `revocationMaterial` enables revocation checks.
  - Submitting sends a `VPRequest` to the Holder's listener and transitions the Verifier to an "awaiting" state.
- **Active Request Panel**: While the Verifier awaits a response, the dashboard displays the pending request with its requested fields and a pulsing status indicator. Auto-refreshes every 3 seconds.
- **Presentation Results**: Each verification result shows an enriched breakdown:
  - **Cryptographic Proof (BBS+ ZKP)**: Whether the zero-knowledge proof verified against the issuer's public key and bound nonce.
  - **Field Completeness**: Whether all requested attributes were present in the disclosed set.
  - **Expiration Check**: Whether `validUntil` is in the future relative to the presentation timestamp. Shown as N/A if `validUntil` was not requested.
  - **Revocation Check**: Whether the credential's bit index is active in the issuer's bitstring. Only performed when `revocationMaterial` was among the disclosed fields, and preempted by fetching the issuer's latest data from the registry. Shown as N/A if not disclosed.
  - **Overall Verdict**: All applicable checks must pass for a VALID result.
- **Protocol Trails**: Full interaction trail log, same pattern as other entity UIs.

---

## 4. Registry UI (`registry/app.py` & port 8001)

Provides a simple administrative view of the centralized registry.

### Key Features
- **Registered Issuers**: A list of all issuers that have broadcast their `IssuerPublicData` to the registry.
- **Schema & Configuration Display**: Each record expands to show the issuer's public key, configured epoch size, complete revocation bitstring, and advertised `CredentialSchema`.
- **Management**: Allows manual deletion of an issuer record from the central store.

---

## Aesthetics & Design

The UI is built with raw HTML/CSS (no heavy frontend frameworks like React or Tailwind) utilizing a consistent "terminal-inspired" dark mode aesthetic (`style.css`):
- Monospace typography (`Cascadia Mono`, `Fira Code`)
- High-contrast neon accents (blue for Holder, purple for Verifier, shared green/red/yellow indicators)
- Extensive use of HTML5 `<details>` for clean, collapsible JSON and data displays.
- Auto-refresh polling (3-second interval) on Holder and Verifier dashboards for real-time VP workflow interaction.
