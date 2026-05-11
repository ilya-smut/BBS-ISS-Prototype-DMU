# Endpoints — Transport & Orchestration Layer

This package implements the application-level transport and orchestration layer that sits on top of the cryptographic entities. It provides transport-agnostic communication abstractions, protocol flow orchestration, and execution trail logging.

## Architecture

```
endpoints/
├── endpoint.py          # Endpoint ABC — client-side transport adapter
├── listener.py          # Listener ABC — server-side transport adapter
├── loopback.py          # LocalLoopbackEndpoint — in-process JSON serialization
├── flask_endpoint.py    # FlaskEndpoint — HTTP client via requests library
├── flask_listener.py    # FlaskListener — Flask server with orchestrator delegation
├── orchestrator.py      # Entity-perspective protocol orchestrators
└── trail.py             # Protocol execution trail recorder
```

### Layering

```
┌─────────────────────────────────┐
│         Orchestrators           │  ← Protocol flow logic
│   (Holder/Issuer/Verifier/Reg)  │
├─────────────────────────────────┤
│     Endpoints / Listeners       │  ← Transport abstraction
│   (Loopback, Flask, ...)        │
├─────────────────────────────────┤
│          Entities               │  ← Cryptographic state machines
│   (Holder/Issuer/Verifier/Reg)  │
└─────────────────────────────────┘
```

---

## `endpoint.py` — Endpoint (ABC)

Transport adapter for outbound communication with a remote entity. An Endpoint is a **client-side proxy** — it serializes requests, transmits them, and deserializes responses.

| Method | Description |
|--------|-------------|
| `send(request)` | One-way: transmit without expecting a response |
| `receive()` | Block until a response arrives and return it |
| `exchange(request)` | Request-response: `send()` + `receive()` |

### Implementations

| Class | Transport | Description |
|-------|-----------|-------------|
| `LocalLoopbackEndpoint` | In-process | Wraps a local Entity instance. Serializes via `to_json()`/`from_json()` to validate the serialization layer. Used for unit tests and local demos. |
| `FlaskEndpoint` | HTTP | POSTs JSON to a remote Flask server via the `requests` library. Configurable HTTP timeout (default: `DEFAULT_HTTP_TIMEOUT_SECONDS = 30`). Raises `ReadTimeout` if the remote server doesn't respond within the configured duration. |

---

## `listener.py` — Listener (ABC)

Server-side counterpart of Endpoint. A Listener receives incoming protocol messages from remote Orchestrators, routes them to the local Entity's `process_request()`, and returns responses over the transport layer.

| Method | Description |
|--------|-------------|
| `start()` | Start the listener server |
| `stop()` | Stop the listener server |

### `flask_listener.py` — FlaskListener

Flask-based server that handles requests at a configurable route (default: `/process`).

**Key design decisions:**

- **JSON key ordering**: Uses `json.dumps(sort_keys=False)` instead of Flask's `jsonify()`, which sorts keys alphabetically. Key order preservation is critical for BBS+ signature verification, as credential subject field ordering maps directly to BBS+ message indices.
- **Orchestrator delegation**: For messages that require protocol-level handling (VP_REQUEST, FORWARD_VP), the listener delegates to the orchestrator rather than processing them at the entity level. This keeps entity logic transport-agnostic.

| Request Type | Handling |
|-------------|----------|
| `VP_REQUEST` | Queued in `orchestrator.pending_requests` (Holder consent checkpoint) |
| `FORWARD_VP` | Delegated to `orchestrator.complete_presentation()` (Verifier verification) |
| All others | Dispatched to `entity.process_request()` directly |

---

## `orchestrator.py` — Protocol Orchestrators

Orchestrators are the primary interaction interface. Each orchestrator wraps a single local Entity and holds Endpoint handles to other participants. They implement multi-step protocol flows as single method calls.

### Error Recovery

All orchestrator flow methods wrap their logic in `try/except`. On any exception (transport failure, unexpected error):

1. `self.entity.reset()` is called to return the entity to idle.
2. The exception is recorded in the trail via `mark_exception()`.
3. The trail is returned with status `FAILED`.

For protocol-level errors (`ErrorResponse` from the Issuer), the orchestrator passes it to the entity's `process_request()` (which calls `end_interaction()`) and marks the trail via `mark_failed()`.

### Base: `Orchestrator`

| Method | Description |
|--------|-------------|
| `_get_endpoint(name)` | Retrieve a named endpoint handle |

### `HolderOrchestrator`

Drives issuance, re-issuance, and presentation flows from the Holder's perspective.

| Method | Description |
|--------|-------------|
| `execute_issuance(issuer_name, attributes, cred_name)` | Full 4-step issuance: request → freshness → blind sign → forward VC. Handles registry resolution on cache miss. Returns a `RequestTrail`. |
| `execute_re_issuance(vc_name, always_hidden_keys)` | Full re-issuance: request → freshness → VP+commitment → new VC. |
| `execute_presentation(vp_request, vc_name, always_hidden_keys)` | Builds VP from pending request, then auto-sends to the Verifier endpoint. Returns `(trail, ForwardVPResponse)`. |
| `sync_registry()` | Bulk-syncs the local cache with the Registry. |
| `pending_requests` | List of queued `VPRequest` messages awaiting user consent. |
| `get_pending_requests()` | Returns and clears the pending queue. |

### `IssuerOrchestrator`

Drives registry registration and updates.

| Method | Description |
|--------|-------------|
| `register_with_registry()` | Full registration handshake with the Registry. |
| `update_registry()` | Updates existing metadata in the Registry. |

### `VerifierOrchestrator`

Drives presentation requests and verification, with optional VP timeout.

| Method | Description |
|--------|-------------|
| `announce_presentation(attrs)` | Generate a VPRequest (local mode — caller delivers it). Starts timeout timer. |
| `send_presentation_request(attrs)` | Generate a VPRequest and POST it to the Holder endpoint. Starts timeout timer. |
| `complete_presentation(forward_vp)` | Verify a received VP. Cancels timeout timer. Handles registry resolution. |
| `verification_results` | List of `(valid, attrs, vp)` tuples from completed verifications. |

**VP Timeout**: Configurable via `vp_timeout_seconds` constructor parameter. When set, a background `threading.Timer` resets the Verifier entity's state if no VP response arrives within the configured duration. The timer is cancelled when `complete_presentation()` is called.

### `RegistryOrchestrator`

Thin wrapper for the passive Registry entity. No outbound flows.

---

## `trail.py` — Protocol Execution Trail

Records the sequence of protocol messages exchanged during a single flow.

### `RequestTrail`

| Field | Description |
|-------|-------------|
| `protocol` | Flow name (e.g., "ISSUANCE", "PRESENTATION_REQUEST") |
| `status` | `IN_PROGRESS`, `COMPLETED`, or `FAILED` |
| `error` | Error description if failed |
| `entries` | List of `TrailEntry` records |

Each `TrailEntry` captures: step number, UTC timestamp, sender, receiver, request type, and the full `get_print_string()` output of the message.

`print_trail(verbose=True)` renders a formatted multi-line summary suitable for console output and demo scripts.
