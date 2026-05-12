# Scripts — Per-Entity Bootstrap & Docker Entrypoints

This directory provides standalone bootstrap functions and Docker entrypoint scripts for deploying each protocol entity as an independent process (or container).

## `flask_bootstrap.py` — Bootstrap Functions

Each function creates a single entity instance, wires it with `FlaskEndpoint` handles to its protocol counterparts, starts a `FlaskListener`, and returns the orchestrator. All parameters default to `localhost` with `DefaultPorts`, enabling zero-argument calls for single-machine use.

### `holder_bootstrap(...) → HolderOrchestrator`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `holder_port` | `5004` | Listener bind port |
| `issuer_base` | `http://localhost` | Issuer server base URL |
| `issuer_port` | `5001` | Issuer server port |
| `verifier_base` | `http://localhost` | Verifier server base URL |
| `verifier_port` | `5002` | Verifier server port |
| `registry_base` | `http://localhost` | Registry server base URL |
| `registry_port` | `5003` | Registry server port |

The Holder listener receives the orchestrator reference for VP_REQUEST queuing.

### `issuer_bootstrap(...) → IssuerOrchestrator`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `name` | `"Test-University"` | Issuer identity (pushed via `set_issuer_parameters()`) |
| `issuer_port` | `5001` | Listener bind port |
| `registry_base` | `http://localhost` | Registry server base URL |
| `registry_port` | `5003` | Registry server port |

The Issuer listener does **not** receive an orchestrator — issuance is handled reactively via `entity.process_request()`.

### `verifier_bootstrap(...) → VerifierOrchestrator`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `verifier_port` | `5002` | Listener bind port |
| `holder_base` | `http://localhost` | Holder server base URL |
| `holder_port` | `5004` | Holder server port |
| `registry_base` | `http://localhost` | Registry server base URL |
| `registry_port` | `5003` | Registry server port |

The Verifier listener receives the orchestrator reference for FORWARD_VP handling.

### `registry_bootstrap(...) → RegistryOrchestrator`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `registry_port` | `5003` | Listener bind port |

The Registry has no outbound endpoints — it is purely reactive.

---

## Docker Entrypoint Scripts

Each `run_*.py` script is a minimal entrypoint designed to be invoked via `python -m bbs_iss.demo.scripts.run_<entity>`. They:

1. Read network topology from **environment variables** (e.g., `REGISTRY_BASE`, `ISSUER_PORT`).
2. Call the corresponding bootstrap function.
3. Keep the main thread alive so the daemon Flask thread persists.
4. Handle `SIGTERM` for graceful container shutdown.

| Script | Entity | Environment Variables |
|--------|--------|----------------------|
| `run_holder.py` | Holder | `HOLDER_PORT`, `ISSUER_BASE/PORT`, `VERIFIER_BASE/PORT`, `REGISTRY_BASE/PORT` |
| `run_issuer.py` | Issuer | `ISSUER_PORT`, `REGISTRY_BASE/PORT` |
| `run_verifier.py` | Verifier | `VERIFIER_PORT`, `HOLDER_BASE/PORT`, `REGISTRY_BASE/PORT` |
| `run_registry.py` | Registry | `REGISTRY_PORT` |

All environment variables are optional — defaults fall back to `localhost` with `DefaultPorts`.

---

## Usage

### Single-Machine (Local)

```python
import bbs_iss.demo.scripts.flask_bootstrap as bootstrap

# Boot all four entities on localhost with default ports
registry_orch = bootstrap.registry_bootstrap()
issuer_orch   = bootstrap.issuer_bootstrap(name="Test-University")
holder_orch   = bootstrap.holder_bootstrap()
verifier_orch = bootstrap.verifier_bootstrap()

# Drive protocol flows via orchestrators
issuer_orch.register_with_registry()
trail = holder_orch.execute_issuance("Test-University", attributes, "cred-1")
```

### Docker Compose (Multi-Container)

From the project root:

```bash
docker compose up --build
```

This starts four containers on a shared bridge network. Docker's embedded DNS resolves service names (`http://registry`, `http://issuer`, etc.) to container IPs automatically. See `docker-compose.yml` in the project root.
