# Scripts — Per-Entity Bootstrap & Docker Entrypoints

This directory provides standalone bootstrap functions and Docker entrypoint scripts for deploying each protocol entity as an independent process (or container).

## `flask_bootstrap.py` — Bootstrap Functions

Each function creates a single entity instance, wires it with `FlaskEndpoint` handles to its protocol counterparts, starts a `FlaskListener`, and returns the orchestrator. 

### Technical Implementation: Multi-Threaded Hosting
To enable both the Protocol Listener and the Web UI to run in a single process, the bootstrap functions utilize Python's `threading` module:
```python
# Protocol Listener runs in a background daemon thread
listener = FlaskListener(entity, port=protocol_port, orch=orch)
listener.start()

# Web UI also runs in a background daemon thread
ui_app = create_..._ui(orch, port=ui_port)
Thread(target=ui_app.run, kwargs={"port": ui_port, "debug": False, "use_reloader": False}, daemon=True).start()
```
This allows each entity to act as a self-contained microservice that exposes both a machine-to-machine API and a human-to-machine dashboard simultaneously.

---

## Docker Entrypoint Scripts

Each `run_*.py` script is a minimal entrypoint designed to be invoked via `python -m bbs_iss.demo.scripts.run_<entity>`. They:

1. Read network topology and UI ports from **environment variables** (e.g., `REGISTRY_BASE`, `ISSUER_UI_PORT`).
2. Call the corresponding bootstrap function.
3. **Main Loop**: Keeps the main thread alive with a `while True: time.sleep(1)` loop, as both the listener and UI are running in daemon threads.
4. **Signal Handling**: Implements a `SIGTERM` handler to ensure graceful container shutdown.

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
