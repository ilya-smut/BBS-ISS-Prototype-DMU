# UI — Browser-Based Interface

This package provides lightweight, browser-based Flask applications for interacting with the core protocol entities. These interfaces are designed to demonstrate the end-to-end functionality of the BBS-ISS prototype without requiring command-line intervention.

## Technical Architecture

The UI layer runs on independent Flask servers, separated from the protocol listeners. This ensures that UI polling and administrative actions do not block the cryptographic state machines.

```
ui/
├── holder/      # Port 8004 (Interacts with HolderOrchestrator)
├── issuer/      # Port 8002 (Interacts with IssuerOrchestrator)
├── verifier/    # Port 8003 (Interacts with VerifierOrchestrator)
└── registry/    # Port 8001 (Interacts with RegistryOrchestrator)
```

### Dashboard Synchronization (Short Polling)

To provide a "live" feel across distributed entities, the dashboards implement a **Short Polling** mechanism:

1. **API Endpoints**: Each UI app exposes a `/api/...-count` or `/api/...-results` endpoint that returns a minimal JSON representation of the current state (e.g., total credentials issued, number of verification results).
2. **Client-Side Polling**: A JavaScript `setInterval` (default: 3000ms) triggers a background `fetch` to these endpoints.
3. **State Comparison**: If the returned count differs from the `knownCount` at page-load time, the UI triggers a `window.location.reload()`.

#### Focus-Aware Safety
To prevent the auto-refresh from interrupting user input (e.g., during schema editing or ABAC policy entry), the reload logic includes a focus check:
```javascript
if (document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
    location.reload();
}
```
This ensures that the dashboard only refreshes when the user is not actively interacting with form elements.

---

## 1. Issuer UI (Port 8002)

Provides an interface for configuring the Issuer entity, managing its credential schema, and tracking issued credentials.

### Technical Implementation: Orchestrator Hooking
The Issuer UI uses a **method decoration** pattern to track issued credentials without modifying the core `IssuerInstance`. In `app.py`, the `process_request` method of the underlying entity is wrapped:
```python
original_process = entity.process_request
def hooked_process(request):
    response = original_process(request)
    if isinstance(response, ForwardVCResponse):
        state.add_credential(response.credential) # Extract and log metadata
    return response
entity.process_request = hooked_process
```

---

## 2. Holder UI (Port 8004)

Provides the end-user wallet interface for requesting credentials and reviewing presentation requests.

### Technical Implementation: Two-Phase Presentation
The Holder dashboard manages a `pending_requests` queue. When the Verifier sends a `VPRequest`, the Holder's **Protocol Listener** (Port 5004) catches it and pushes it into the Orchestrator's queue. The UI Polling detects this change and refreshes to show the new request.

**Consent Transparency**: Before the user provides consent, the `present.html` template performs a local lookup in the Holder's wallet. It extracts and displays the actual attribute values contained in the selected credential, allowing the user to verify exactly what data is being disclosed before it is blinded into a ZKP.

---

## 3. Verifier UI (Port 8003)

Provides an interface for requesting verifiable presentations and performing policy-level ABAC checks.

### Technical Implementation: ABAC Engine
The Verifier UI extends the cryptographic verification with a policy matching layer. 
- **Predicate Parsing**: Supports the `dateOfBirth` attribute with chronological operators. The engine uses a regular expression to split the policy into an operator and a target date: `r'^(<=|>=|<|>|==)?(\d{2}-\d{2}-\d{4})$'`.
- **Granular Feedback**: Instead of a simple pass/fail, the backend populates an `abac_mismatches` list. The UI template iterates through disclosed fields and highlights only the specific attributes that failed the policy check.

---

## 4. Registry UI (Port 8001)

An administrative view of the centralized registry storage.

### Technical Implementation: Unified Orchestration
Previously passive, the Registry UI now utilizes a `RegistryOrchestrator`. This unifies the bootstrap pattern across all entities, allowing the Registry to maintain a standard `RequestTrail` log and support the same auto-refresh polling as the other entities.

---

## Design Aesthetic

The UI utilizes a "Terminal-Neon" aesthetic defined in `style.css`:
- **Typography**: `Cascadia Mono`, `Fira Code`, or `monospace` fallback.
- **Micro-Animations**: Subtle pulsing indicators for "AWAITING" states and smooth hover transitions on interactive badges.
- **Standardized Elements**: Shared CSS variables for entity-specific colors (e.g., `--holder-blue`, `--verifier-purple`).

