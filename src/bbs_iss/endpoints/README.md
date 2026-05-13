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

### Technical Implementation: JSON Serialization Constraints
BBS+ signatures are highly sensitive to the order of bytes in the message vector. Standard Python `json.dumps` and Flask `jsonify()` often sort dictionary keys alphabetically, which would alter the deterministic `metaHash` and break signature verification.
- **Design Choice**: The `FlaskListener` uses `json.dumps(obj, sort_keys=False)` to preserve the exact insertion order of the attributes provided by the entities.

### Technical Implementation: Listener Delegation
The `FlaskListener` is more than a simple router. It acts as a **Middleware** for the protocol:
- **Reactive Messages**: Standard protocol messages (e.g., `ISSUANCE`, `FRESHNESS`, `BLIND_SIGN`) are dispatched directly to `entity.process_request()`.
- **Orchestration-Aware Messages**: Messages like `VP_REQUEST` and `FORWARD_VP` require asynchronous handling or multi-step logic that the cryptographic entity shouldn't know about. The listener intercepts these and calls specific orchestrator methods (`get_pending_requests()` or `complete_presentation()`), allowing the orchestrator to manage the high-level state (e.g., consent queues or timeout timers) while the entity remains "pure".

---

## `orchestrator.py` — Protocol Orchestrators

### Technical Implementation: Error Recovery & State Resets
Orchestrators ensure that a failure in one protocol session does not poison the entity for future sessions.
- **Mechanism**: Every flow method is wrapped in a global `try/except`. 
- **Action**: On any exception (network timeout, malformed JSON, or cryptographic failure), the orchestrator calls `self.entity.reset()`. This clears the entity's internal "Busy" flag and discards any partial session state (nonces, commitments), returning it to `available=True`.

### Technical Implementation: Verifier VP Timeout
To prevent the Verifier from hanging indefinitely in an `AWAITING_VP` state, the orchestrator implements a background watchdog:
- **Timer**: When a `VPRequest` is sent, a `threading.Timer` is started.
- **Cancellation**: If `complete_presentation()` is called before the timer expires, the timer is cancelled.
- **Expiration**: If the timer expires, it automatically calls `self.entity.reset()`, marking the verifier as available for the next interaction.

