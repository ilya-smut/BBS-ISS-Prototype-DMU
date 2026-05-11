# Demo — Demo Setup & Configuration

This package contains convenience wiring helpers and configuration presets for demo environments.

## `demo_configuration.py` — Centralised Defaults

All demo-specific constants in one place:

### `DefaultRoutes`

Standardised URL paths for Flask entity servers.

| Constant | Value | Description |
|----------|-------|-------------|
| `PROCESS` | `"/process"` | The endpoint path for all protocol messages |

### `DefaultPorts`

Default port assignments for networked Flask demos.

| Constant | Value | Entity |
|----------|-------|--------|
| `ISSUER` | `5001` | Issuer server |
| `VERIFIER` | `5002` | Verifier server |
| `REGISTRY` | `5003` | Registry server |
| `HOLDER` | `5004` | Holder server |

### `DefaultEntityNames`

Default entity identifiers used in demo scenarios.

| Constant | Value |
|----------|-------|
| `ISSUER` | `"Test-University"` |
| `HOLDER` | `"Demo-Holder"` |
| `VERIFIER` | `"Demo-Verifier"` |
| `REGISTRY` | `"Demo-Registry"` |

### `DEFAULT_VP_TIMEOUT_SECONDS`

Default timeout for Verifier VP interactions: **60 seconds**.

### `DEFAULT_HTTP_TIMEOUT_SECONDS`

Default timeout for HTTP requests via `FlaskEndpoint`: **30 seconds**. If a remote server does not respond within this duration, `requests.exceptions.ReadTimeout` is raised and the orchestrator records the failure in the trail.

---

## `local_demo_setup.py` — In-Process Wiring

`create_local_demo(issuer, holder, verifier, registry)` wires four entity instances into orchestrators connected via `LocalLoopbackEndpoint`s. All communication stays in-process with JSON serialization round-trips to validate the serialization layer.

Used by: unit tests (`test_orchestrator.py`), local demo scripts (`orch_demo.py`).

---

## `flask_demo_setup.py` — Networked Flask Wiring

`create_flask_demo(issuer, holder, verifier, registry, ...)` wires four entity instances for networked operation:

1. Creates `FlaskEndpoint` client handles for each entity pair.
2. Creates orchestrators with the appropriate endpoint handles.
3. Starts `FlaskListener` servers on dedicated ports (configurable, defaults from `DefaultPorts`).
4. Verifier and Holder listeners receive orchestrator handles for VP delegation.

**Topology (single machine):**

```
Registry:  http://localhost:5003/process
Issuer:    http://localhost:5001/process
Verifier:  http://localhost:5002/process
Holder:    http://localhost:5004/process
```

Used by: `testing/flask_demo.py`, Flask transport integration tests.
