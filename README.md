# BBS-ISS-Prototype-DMU

A proof-of-concept Python prototype for a **Privacy-Preserving Verifiable Credential System** using **BBS+ signatures and Zero-Knowledge Proofs (ZKPs)**.

Built on top of the `ursa_bbs_signatures` library, this project implements a blind credential issuance protocol with Pedersen commitments, selective disclosure presentations with bound nonces, credential renewal (re-issuance), and epoch-based revocation.

---

## Getting Started

### Prerequisites
- Python >= 3.10
- `ursa-bbs-signatures` >= 1.0.1
- `flask` >= 3.0 (for UI/networked modes)
- `requests` >= 2.31

### Installation & Setup

We provide an automated setup script to build the virtual environment and install the required dependencies (including local FFI library wrapper):

```bash
# Run the setup script
./setup.sh

# Activate the virtual environment
source .venv/bin/activate
```

### Running the Project

- **Unit Tests**:
  ```bash
  pytest
  ```
- **CLI Demo (Local Loopback)**:
  ```bash
  python testing/demo.py
  ```
- **CLI Demo (Networked Flask)**:
  ```bash
  python testing/flask_demo.py
  ```
- **Web UI Check (All 4 Entities)**:
  ```bash
  python testing/ui_check.py
  ```
  This runs all UI servers. Once running, you can access the dashboards in your browser:
  - **Registry**: http://localhost:8001
  - **Issuer**: http://localhost:8002
  - **Verifier**: http://localhost:8003
  - **Holder**: http://localhost:8004

---

## Project Structure

```
BBS-ISS-Prototype-DMU/
├── setup.sh
├── pyproject.toml
├── README.md
├── BBS_LIBRARY_FIX.md
├── BLINDED_COMMITMENT_NOTE.md
├── vendor/               # Patched version of ffi-bbs-signatures
├── src/
│   └── bbs_iss/
│       ├── entities/     # Cryptographic state machines (Issuer, Holder, Verifier, Registry)
│       ├── interfaces/   # JSON/dict API models and Verifiable Credentials
│       ├── endpoints/    # Pluggable transport adapters (Flask, loopback) and orchestrators
│       ├── ui/           # Flask-based web interface apps for the entities
│       ├── exceptions/   # Domain-specific exceptions
│       └── utils/        # General utilities (cryptographic nonce generators, caches)
└── testing/              # Unit tests and end-to-end demo scripts
```

---

## Cryptographic Library Patches

Due to compatibility bugs in the upstream `ursa_bbs_signatures` package (like issues during blind signing or serialization of G2 points), we vendor a patched version of the wrapper under `vendor/ffi-bbs-signatures/`.
See [BBS_LIBRARY_FIX.md](BBS_LIBRARY_FIX.md) for full details on the modifications.
A discussion of the security properties of commitment verification is available in [BLINDED_COMMITMENT_NOTE.md](BLINDED_COMMITMENT_NOTE.md).
