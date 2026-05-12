# BBS-ISS-Prototype-DMU

A working proof-of-concept Python prototype for a **Privacy-Preserving Verifiable Credential System** utilizing **BBS+ signatures and Zero-Knowledge Proofs (ZKPs)**. Built on top of the [`ursa_bbs_signatures`](https://pypi.org/project/ursa-bbs-signatures/) library, this prototype demonstrates a complete, secure credential lifecycle: multi-round blind issuance with Pedersen commitments, verifiable presentation generation with cryptographic binding, seamless credential re-issuance, and foundational revocation mechanics.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Architecture Overview](#architecture-overview)
- [Protocol Design](#protocol-design)
  - [Issuance Protocol](#issuance-protocol)
  - [Presentation Protocol](#presentation-protocol)
  - [Re-issuance Protocol](#re-issuance-protocol)
  - [Registry Synchronization](#registry-synchronization)
  - [Epoch-Based Expiration](#epoch-based-expiration)
  - [Error Handling](#error-handling)
- [System Architecture](#system-architecture)
  - [Roles & Entities](#roles--entities)
  - [Request Message Structure](#request-message-structure)
  - [Transport Layer](#transport-layer)
  - [Orchestrators](#orchestrators)
  - [Listeners](#listeners)
  - [Consent Mechanism](#consent-mechanism)
- [Project Structure](#project-structure)
- [Detailed Protocol Flows (Sequence Diagrams)](PROTOCOL_FLOWS.md)
- [Known Issues & Library Fixes](#known-issues--library-fixes)

---

## Prerequisites

- Python ≥ 3.10
- `ursa-bbs-signatures` ≥ 1.0.1
- `flask` ≥ 3.0 (networked mode)
- `requests` ≥ 2.31 (networked mode)

## Installation

An automated setup script is provided to initialize submodules, build the virtual environment, and install all dependencies (including the vendored FFI cryptography library).

```bash
# Clone the repository
git clone git@github.com:ilya-smut/BBS-ISS-Prototype-DMU.git
cd BBS-ISS-Prototype-DMU

# Run the automated setup script
./setup.sh

# Activate the virtual environment before running the project
source .venv/bin/activate
```

### Running Tests

```bash
pytest testing/unit/
```

### Running the Networked Demo

```bash
python testing/flask_demo.py
```

### Running with Docker Compose

Each entity can be deployed as an independent container using the provided `Dockerfile` and `docker-compose.yml`:

```bash
docker compose up --build
```

This starts four containers (Registry, Issuer, Verifier, Holder) on a shared bridge network. Docker's embedded DNS resolves service names (`http://registry`, `http://issuer`, etc.) to container IPs automatically. Each container runs a single entity via the entrypoint scripts in `src/bbs_iss/demo/scripts/`.

Network topology is configured via environment variables in `docker-compose.yml`. See [`scripts/README.md`](src/bbs_iss/demo/scripts/README.md) for the full parameter reference.

---

## Architecture Overview

The system follows a **three-layer architecture**, separating cryptographic logic from transport and orchestration:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Orchestration Layer                          │
│  HolderOrchestrator · IssuerOrchestrator · VerifierOrchestrator  │
│  Multi-step flow logic, consent checkpoints, VP timeout          │
├─────────────────────────────────────────────────────────────────┤
│                      Transport Layer                             │
│  Endpoints (client) ←→ Listeners (server)                        │
│  LocalLoopback (in-process) · Flask/HTTP (networked)             │
├─────────────────────────────────────────────────────────────────┤
│                      Entity Layer                                │
│  IssuerInstance · HolderInstance · VerifierInstance · Registry     │
│  BBS+ signing, commitment verification, ZKP generation           │
│  State machines, cache management, revocation tracking            │
└─────────────────────────────────────────────────────────────────┘
```

- **Entities** are cryptographic state machines with no transport awareness.
- **Endpoints / Listeners** provide pluggable transport (swap `LocalLoopbackEndpoint` for `FlaskEndpoint` to move from in-process simulation to real HTTP).
- **Orchestrators** compose multi-step protocol flows from entity method calls and endpoint exchanges.

---

## Protocol Design

### Issuance Protocol

The blind issuance protocol proceeds in four rounds between the **Holder** and the **Issuer**:

```
Holder                                        Issuer
  │                                              │
  │──── 1. VCIssuanceRequest ───────────────────>│
  │                                              │
  │<─── 2. FreshnessUpdateResponse (nonce) ──────│
  │                                              │
  │──── 3. BlindSignRequest ────────────────────>│
  │     (commitment, proof, revealed attrs)      │
  │                                              ├── verify commitment proof
  │                                              ├── build VC skeleton
  │                                              ├── compute blind signature
  │<─── 4. ForwardVCResponse (VC w/ blind sig) ──│
  │                                              │
  ├── unblind signature                          │
  ├── verify full BBS+ signature                 │
  └── store credential                           │
```

1. **Issuance Request**: Holder initiates by signaling intent. Holder resolves the Issuer's public key via cache or registry lookup.
2. **Freshness Response**: Issuer generates a random 32-byte nonce for session binding.
3. **Blind Sign Request**: Holder builds a Pedersen commitment over hidden attributes using the nonce, appends metadata attributes (`metaHash`, `validUntil`, `revocationMaterial`), and sends the commitment, proof, and revealed attributes.
4. **Forward VC Response**: Issuer verifies the commitment proof, constructs the VC, computes a blind BBS+ signature, and returns the signed credential. Holder unblinds, verifies, and stores.

---

### Presentation Protocol

Selective disclosure via zero-knowledge proof:

```
Verifier                                      Holder
  │                                              │
  │──── 1. VPRequest ───────────────────────────>│
  │     (requested attrs, challenge nonce)       │
  │                                              ├── resolve credential
  │                                              ├── build VP with requested attrs
  │                                              ├── derive bound nonce
  │                                              ├── create BBS+ ZKP proof
  │<─── 2. ForwardVPResponse ────────────────────│
  │     (VP, issuer_pub_key)                     │
  ├── check attribute completeness               │
  ├── reconstruct bound nonce                    │
  ├── verify BBS+ ZKP                            │
  └── extract revealed attributes                │
```

The **bound nonce** cryptographically ties the VP's metadata envelope to the Verifier's challenge, preventing cross-session replay. Both parties independently compute this value from the same inputs.

---

### Re-issuance Protocol

Credential renewal that proves possession of the old credential while requesting a new one:

```
Issuer                                        Holder
  │                                              │
  │<─── 1. Re-issuance Request ──────────────────│
  │                                              │
  │──── 2. FreshnessUpdateResponse (nonce) ─────>│
  │                                              │
  │<─── 3. ForwardVpAndCmtRequest ───────────────│
  │     (VP of old VC, new commitment)           │
  ├── verify VP & old VC validity                │
  ├── check re-issuance window                   │
  ├── verify commitment proof (bound to nonce)   │
  ├── revoke old index                           │
  ├── compute blind signature for new VC         │
  │──── 4. ForwardVCResponse (new VC) ──────────>│
  │                                              │
  │                                              ├── unblind new signature
  │                                              ├── verify new signature
  │                                              └── store new credential
```

---

### Registry Synchronization

The Registry acts as an authoritative source for Issuer public data. Entities maintain a local `PublicDataCache` and implement a **Cache-First** resolution strategy:

```
Entity (Holder/Verifier)                         Registry
  │                                              │
  ├── check local cache (miss) ──┐               │
  │                              │               │
  ├── suspend interaction <──────┘               │
  │                                              │
  │──── 1. GetIssuerDetailsRequest ─────────────>│
  │                                              ├── lookup issuer metadata
  │<─── 2. IssuerDetailsResponse (metadata) ─────│
  │                                              │
  ├── update local cache                         │
  └── resume suspended interaction               │
```

When an entity encounters an unknown Issuer mid-protocol, it suspends the current interaction, resolves via the Registry, and automatically resumes. This provides transparent asynchronous resolution.

---

### Epoch-Based Expiration

To prevent timeline-based correlation attacks, all credentials are aligned to a rigid global epoch grid:

- **Global Alignment**: Expiration is calculated as distance from a fixed `baseline_date`, not dynamically from `now`. All credentials issued within the same cycle expire on the exact same second.
- **Window Bumping**: Credentials issued within the `re_issuance_window_days` of an upcoming boundary are automatically rolled to the next epoch.

---

### Schema-Driven Architecture

The prototype enforces structural consistency using a standardized `CredentialSchema` model:

- **Strict Attribute Ordering**: To maintain BBS+ cryptographic integrity, all credentials strictly separate and order revealed and hidden (`LinkSecret`) attributes within the message indices, preventing index misalignment during selective disclosure.
- **Dynamic Inference**: `VerifiableCredential` and `VerifiablePresentation` objects dynamically infer their `type` and `@context` from the schema, ensuring forward-compatibility with any custom W3C formats without hardcoding.
- **Schema Caching**: Issuers advertise their schema to the Registry. Holders cache this structural metadata and use it to dynamically render UI forms that automatically enforce the correct key structures for issuance requests.

---

### Error Handling

Instead of propagating raw exceptions, the Issuer returns structured `ErrorResponse` messages with typed error categories:

| Error Type | Trigger |
|------------|---------|
| `ISSUER_UNAVAILABLE` | Concurrent session attempts |
| `VERIFICATION_FAILED` | Tampered proofs or invalid commitments |
| `BITSTRING_EXHAUSTED` | Revocation capacity exceeded |
| `INVALID_REQUEST` | Malformed payloads |
| `INVALID_STATE` | Out-of-order protocol messages |

Upon receiving an `ErrorResponse`, entities automatically reset their state machines.

---

## System Architecture

### Roles & Entities

| Role | Entity Class | Description |
|------|-------------|-------------|
| **Issuer** | `IssuerInstance` | Key generation, blind signing, VC construction, revocation management |
| **Holder** | `HolderInstance` | Commitment building, credential storage, ZKP proof generation |
| **Verifier** | `VerifierInstance` | Challenge nonce generation, ZKP verification, validity checks |
| **Registry** | `RegistryInstance` | Authoritative metadata storage, bulk synchronization |

Each entity is a self-contained state machine. They process protocol messages via `process_request()` and have no awareness of transport or orchestration.

### Request Message Structure

All protocol messages inherit from `Request` and carry a `request_type` discriminator. The system supports:

- **Polymorphic serialization**: `to_dict()` / `from_dict()` / `to_json()` / `from_json()` with automatic hex encoding for binary fields.
- **Polymorphic reconstruction**: `Request.from_dict()` inspects the `request_type` discriminator and reconstructs the correct subclass, enabling transport layers to receive generic JSON and reconstruct typed objects.
- **Rich diagnostics**: `get_print_string()` produces human-readable bordered output for debugging and protocol trail logging.

### Transport Layer

The transport layer is **pluggable** — the same orchestrator logic works with both local simulation and real HTTP by swapping the Endpoint implementation:

```
         Orchestrator
             │
    ┌────────┴────────┐
    │                 │
LocalLoopback    FlaskEndpoint
(in-process)     (HTTP POST)
```

| Component | Role | Description |
|-----------|------|-------------|
| `Endpoint` (ABC) | Client | Serializes and transmits requests. Methods: `send()`, `receive()`, `exchange()` |
| `Listener` (ABC) | Server | Receives requests, dispatches to entity, returns responses |
| `LocalLoopbackEndpoint` | Client | In-process JSON round-trip through a local entity reference |
| `FlaskEndpoint` | Client | HTTP POST via the `requests` library |
| `FlaskListener` | Server | Flask server with key-order-preserving JSON responses (critical for BBS+) |

**Key design constraint**: Flask's default `jsonify()` sorts dictionary keys alphabetically, which breaks BBS+ signature verification (message ordering is semantic). The `FlaskListener` uses `json.dumps(sort_keys=False)` to preserve insertion order.

### Orchestrators

Orchestrators are the primary interaction interface for users and demo scripts. Each wraps a single entity and holds endpoint handles to other participants:

| Orchestrator | Entity | Drives |
|-------------|--------|--------|
| `HolderOrchestrator` | Holder | Issuance, re-issuance, presentation execution |
| `IssuerOrchestrator` | Issuer | Registry registration, metadata updates |
| `VerifierOrchestrator` | Verifier | Presentation requests, VP verification, timeout |
| `RegistryOrchestrator` | Registry | Passive (no outbound flows) |

Orchestrators compose multi-step protocols into single method calls:

```python
# Full 4-step issuance in one call
trail = holder_orch.execute_issuance("University", attributes, "my-cred")

# Generate VPRequest and send to Holder over HTTP
trail, vp_req = verifier_orch.send_presentation_request(["name", "degree"])

# Holder reviews pending queue and consents
pending = holder_orch.get_pending_requests()
trail, vp = holder_orch.execute_presentation(pending[0], "my-cred")
```

### Listeners

In networked mode, each entity runs a `FlaskListener` that receives incoming HTTP requests. The listener handles two categories:

1. **Generic protocol messages** (issuance, registry) → dispatched directly to `entity.process_request()`.
2. **Orchestrator-level messages** (VP_REQUEST, FORWARD_VP) → delegated to the entity's orchestrator for consent handling or verification result storage.

### Consent Mechanism

The presentation protocol includes a manual consent checkpoint:

1. Verifier sends `VPRequest` to Holder's listener.
2. Listener queues the request in `HolderOrchestrator.pending_requests`.
3. Holder (user) reviews pending requests at their discretion.
4. Upon consent, `execute_presentation()` builds the VP and auto-sends it to the Verifier.
5. Verifier's listener delegates to `VerifierOrchestrator.complete_presentation()` and stores the result.

An optional **VP timeout** (`vp_timeout_seconds`) resets the Verifier's state if no response arrives within the configured duration.

---

## Project Structure

```
BBS-ISS-Prototype-DMU/
├── setup.sh                        # Automated installation script
├── pyproject.toml                  # Package configuration
├── Dockerfile                      # Container image definition
├── docker-compose.yml              # Multi-container orchestration
├── README.md                       # Architecture documentation (this file)
├── PROTOCOL_FLOWS.md               # Detailed sequence diagrams
├── BBS_LIBRARY_FIX.md              # ursa_bbs_signatures bug fixes
├── BLINDED_COMMITMENT_NOTE.md      # Security note on blinded index leakage
├── vendor/
│   └── ffi-bbs-signatures/         # Vendored and patched cryptography library
├── src/
│   └── bbs_iss/                    # Main package
│       ├── entities/               # Protocol participants (see entities/README.md)
│       │   ├── entity.py           # Entity ABC
│       │   ├── issuer.py           # IssuerInstance
│       │   ├── holder.py           # HolderInstance
│       │   ├── verifier.py         # VerifierInstance
│       │   └── registry.py         # RegistryInstance
│       ├── interfaces/             # Data types & serialization (see interfaces/README.md)
│       │   ├── requests_api.py     # Request/response classes, key wrappers
│       │   └── credential.py       # VerifiableCredential, VerifiablePresentation
│       ├── endpoints/              # Transport & orchestration (see endpoints/README.md)
│       │   ├── endpoint.py         # Endpoint ABC (client-side transport)
│       │   ├── listener.py         # Listener ABC (server-side transport)
│       │   ├── loopback.py         # LocalLoopbackEndpoint (in-process)
│       │   ├── flask_endpoint.py   # FlaskEndpoint (HTTP client)
│       │   ├── flask_listener.py   # FlaskListener (Flask server)
│       │   ├── orchestrator.py     # Protocol orchestrators
│       │   └── trail.py            # Execution trail recorder
│       ├── demo/                   # Demo setup & config (see demo/README.md)
│       │   ├── demo_configuration.py  # Default ports, routes, entity names
│       │   ├── local_demo_setup.py    # In-process loopback wiring
│       │   ├── flask_demo_setup.py    # Networked Flask wiring
│       │   └── scripts/               # Per-entity bootstrap (see scripts/README.md)
│       │       ├── flask_bootstrap.py  # Bootstrap functions (parameterised)
│       │       ├── run_holder.py       # Docker entrypoint: Holder
│       │       ├── run_issuer.py       # Docker entrypoint: Issuer
│       │       ├── run_verifier.py     # Docker entrypoint: Verifier
│       │       └── run_registry.py     # Docker entrypoint: Registry
│       ├── exceptions/             # Exception hierarchy (see exceptions/README.md)
│       │   └── exceptions.py
│       └── utils/                  # Utilities (see utils/README.md)
│           ├── utils.py            # Nonce/link-secret generation
│           └── cache.py            # PublicDataCache manager
├── testing/
│   ├── flask_demo.py               # Networked HTTP demo (4 Flask servers)
│   ├── orch_demo.py                # Orchestrator demo (in-process)
│   ├── demo.py                     # Legacy interactive demo
│   └── unit/                       # Pytest test suite (see unit/README.md)
│       ├── entities/               # Entity state machine tests
│       ├── flows/                  # End-to-end protocol flow tests
│       └── models/                 # Data model & serialization tests
└── reference/
    └── main.pdf                    # Reference paper
```

Each `src/bbs_iss/` subdirectory contains its own `README.md` with detailed implementation documentation.

---

## Known Issues & Library Fixes

The `ursa_bbs_signatures` library contains several bugs that required local patches. See [`BBS_LIBRARY_FIX.md`](BBS_LIBRARY_FIX.md) for the full list of fixes applied to the library.

A security note on potential data leakage during blinded commitment verification is documented in [`BLINDED_COMMITMENT_NOTE.md`](BLINDED_COMMITMENT_NOTE.md).

---

## Acknowledgments

This prototype utilizes the Python wrapper and `libbbs.so` components from the [ffi-bbs-signatures](https://github.com/mattrglobal/ffi-bbs-signatures) repository (originally maintained by `mattrglobal` / Hyperledger Aries Contributors) for its underlying cryptographic operations.

A locally patched version of this library is vendored into this project as a Git Submodule under `vendor/ffi-bbs-signatures` to resolve critical execution bugs during blind signing and verify flows. All original rights and open-source licenses (Apache 2.0 / MIT) associated with the `ffi-bbs-signatures` repository remain explicitly applicable to the submodule source.
