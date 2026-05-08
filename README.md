# BBS-ISS-Prototype-DMU

A working proof-of-concept Python prototype for a **Privacy-Preserving Verifiable Credential System** utilizing **BBS+ signatures and Zero-Knowledge Proofs (ZKPs)**. Originally designed within the context of higher education institutions, this project enables individuals (Holders) to obtain digital credentials from organizations (Issuers) and selectively prove statements about their identity to third parties (Verifiers) while prioritizing data minimization and privacy. Built on top of the [`ursa_bbs_signatures`](https://pypi.org/project/ursa-bbs-signatures/) library, the prototype demonstrates a complete, secure credential lifecycle: multi-round blind issuance with Pedersen commitments, verifiable presentation generation with cryptographic binding, seamless credential re-issuance, and foundational revocation mechanics.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Protocol Overview](#protocol-overview)
- [Module Reference](#module-reference)
  - [Entities](#entities)
    - [IssuerInstance](#issuerinstance)
    - [HolderInstance](#holderinstance)
    - [VerifierInstance](#verifierinstance)
    - [RegistryInstance](#registryinstance)
  - [Interfaces](#interfaces)
    - [requests\_api](#requests_api)
    - [credential](#credential)
  - [Exceptions](#exceptions)
  - [Utils](#utils)
- [Usage Example](#usage-example)
- [Known Issues & Library Fixes](#known-issues--library-fixes)

---

## Prerequisites

- Python ≥ 3.10
- `ursa-bbs-signatures` ≥ 1.0.1

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

To run the unit test suite:
```bash
pytest testing/unit/
```

---

## Project Structure

```
BBS-ISS-Prototype-DMU/
├── setup.sh                        # Automated installation script
├── pyproject.toml                  # Package configuration
├── README.md                       # This file
├── BBS_LIBRARY_FIX.md              # Documentation of ursa_bbs_signatures bug fixes
├── BLINDED_COMMITMENT_NOTE.md      # Security note on blinded index data leakage
├── vendor/
│   └── ffi-bbs-signatures/         # Vendored and patched cryptography library
├── src/
│   └── bbs_iss/                    # Main package
│       ├── __init__.py
│       ├── entities/               # Protocol participants
│       │   ├── __init__.py
│       │   ├── issuer.py           # IssuerInstance class
│       │   ├── holder.py           # HolderInstance class
│       │   ├── verifier.py         # VerifierInstance class
│       │   └── registry.py         # RegistryInstance class
│       ├── interfaces/             # Shared data types and protocol messages
│       │   ├── __init__.py
│       │   ├── requests_api.py     # Request/response classes, serialization, pretty-printing
│       │   └── credential.py       # VerifiableCredential and VerifiablePresentation classes
│       ├── exceptions/             # Custom exception hierarchy
│       │   └── exceptions.py       # All project exceptions
│       └── utils/                  # Utility functions
│           ├── utils.py            # Nonce generation, link secret generation
│           └── cache.py            # PublicDataCache manager
├── testing/
│   ├── demo.py                     # High-level end-to-end interactive demonstration
│   └── unit/                       # Pytest comprehensive unit test suite
│       ├── entities/               # Participant state and interaction tests
│       ├── flows/                  # End-to-end multi-round protocol flows
│       └── models/                 # Cryptographic payload, serialization, and cache testing
├── vp-test.py                      # Original end-to-end issuance/presentation script
├── examples/                       # Practical usage demonstrations
│   ├── full_cycle.py               # End-to-end flow with issuance and presentation
│   └── registry.py                 # Demonstration of registry lookups and caching
└── reference/
    └── main.pdf                    # Reference paper
```

---

## Protocol Overview

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
  ├── verify signature                           │
  └── store credential                           │
```

---

### Registry Protocol (Authority Synchronization)

The Registry acts as an authoritative source for Issuer public data. Entities maintain a local `PublicDataCache` and synchronize with the Registry using a "Cache-First" strategy.

**Asynchronous Resolution:** Both the Holder and Verifier implement an asynchronous "Pending" state. If an interaction requires issuer metadata not present in the local cache, the entity suspends the current flow, returns a `GetIssuerDetailsRequest`, and automatically resumes the interaction upon receiving and processing the authoritative `IssuerDetailsResponse`.

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

**Bulk Synchronization:** To facilitate efficient bootstrapping, entities can also perform a `BulkGetIssuerDetailsRequest`, which triggers the Registry to return a complete list of all registered issuers in a single interaction.

**Issuer Registration:** Issuers proactively announce their metadata (Public Key, Epoch configuration, Revocation bitstring) to the Registry via `RegisterIssuerDetailsRequest`.

---

**Step 1 — Issuance Request:** The Holder initiates the protocol by sending a `VCIssuanceRequest`. Internally, the Holder stores the public key, attributes, and credential name in its local state.

**Step 2 — Freshness Response:** The Issuer generates a random 32-byte nonce and returns it as a `FreshnessUpdateResponse`. This value binds the commitment to a specific session, preventing replay attacks.

**Step 3 — Blind Sign Request:** The Holder builds a Pedersen commitment over its blinded attributes using the Issuer's nonce and public key. This step automatically appends three essential revealed metadata attributes: `metaHash` (which deterministically hashes the credential's contextual metadata), `validUntil` (expiration timestamp), and `revocationMaterial` (a bitstring index for future revocation checks). It sends a `BlindSignRequest` containing the commitment, a zero-knowledge proof of correct commitment construction, the revealed attributes, and their indices.

**Step 4 — Forward VC Response:** The Issuer first pre-computes the `VerifiableCredential` skeleton from the revealed and blinded attribute indices, then re-calculates the `metaHash` on the constructed VC and overwrites the placeholder value in both the VC and the signing request. It then verifies the blinded commitment proof. If valid, it computes a blind BBS+ signature over the commitment and the revealed attributes, attaches the signature to the VC, and returns it as a `ForwardVCResponse`.

The Holder then unblinds the signature using its stored blinding factor, fills in the blinded attribute values, re-verifies the signature against the full attribute set (including a freshly re-computed `metaHash`), and stores the credential.

---

### Presentation Protocol (Holder ↔ Verifier)

The selective disclosure protocol enables the Holder to present a verifiable subset of attributes to a Verifier using a zero-knowledge proof without revealing blinded attributes (such as link secrets) or any non-requested attributes.

```
Verifier                                      Holder
  │                                              │
  │──── 1. VPRequest ───────────────────────────>│
  │     (requested attrs, challenge nonce)       │
  │                                              ├── resolve credential
  │                                              ├── verify attribute availability
  │                                              ├── prevent hidden key conflict
  │                                              ├── build Verifiable Presentation
  │                                              ├── derive ZKP proof over bound nonce
  │<─── 2. ForwardVPResponse ────────────────────│
  │     (VP, issuer_pub_key)                     │
  ├── verify attribute completeness              │
  ├── verify BBS+ ZKP                            │
  └── extract revealed attributes                │
```

**Step 1 — VP Request:** The Verifier initiates a presentation by generating a random challenge nonce and sending a `VPRequest` specifying the list of attribute keys it requires.

**Step 2 — Forward VP Response:** The Holder receives the request and resolves the target credential. It ensures all requested attributes are present and none conflict with application-enforced hidden keys (e.g., link secrets). It builds a `VerifiablePresentation` containing only the requested subset. 

To prevent replay attacks and ensure cryptographic binding to the credential envelope, the Holder hashes the VP's envelope with the Verifier's original challenge nonce to derive a **bound nonce**. It then computes a zero-knowledge proof (ZKP) over the original BBS+ signature, utilizing the bound nonce, and attaches the proof to the VP. The VP is returned in a `ForwardVPResponse`.

**Step 3 — Verification:** The Verifier first checks **Attribute Completeness** to ensure the Holder didn't omit required fields. It then reconstructs the **bound nonce** identically to the Holder and verifies the ZKP. If successful, the Verifier safely extracts the revealed attributes.

---

### Re-issuance Protocol (Holder ↔ Issuer)

The re-issuance protocol allows a Holder to request a renewed credential (e.g., updating the `validUntil` timestamp) while proving possession of their original credential via a Verifiable Presentation. This effectively binds the presentation of the old credential to the request for the new one.

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
  ├── verify commitment proof (bound to nonce)   │
  ├── compute blind signature for new VC         │
  │──── 4. ForwardVCResponse (new VC) ──────────>│
  │                                              │
  │                                              ├── unblind new signature
  │                                              ├── verify new signature
  │                                              └── store new credential
```

**Step 1 — Re-issuance Request:** The Holder initiates the process specifying the target credential and the attributes that must remain hidden.

**Step 2 — Freshness Response:** The Issuer generates a challenge nonce for the session.

**Step 3 — Forward VP & Commitment:** The Holder generates a zero-knowledge proof (VP) of the old credential. It also generates a *new* blinded Pedersen commitment over its secret attributes (using the *same* challenge nonce). Both the VP and the new commitment are bundled into a `ForwardVpAndCmtRequest` and sent to the Issuer.

**Step 4 — New VC Response:** The Issuer verifies the VP (proving possession and validity of the old credential), checks the re-issuance window and revocation status, and verifies the new commitment proof against the same nonce. If valid, the Issuer issues a new Verifiable Credential with updated metadata (e.g., `validUntil`) and returns it. The Holder then unblinds and stores the renewed credential.

---

### Epoch-Based Expiration Logic

To prevent timeline-based correlation attacks (where attackers track users across platforms by their unique credential expiration timestamps), this prototype implements strict **Epoch-Based Validity**. 

- **Global Alignment:** Rather than calculating expiration dynamically (e.g., `now + duration`), the system calculates distance from a rigid, system-wide `baseline_date`. All credentials issued within the same cycle expire on the exact same second, granting users absolute temporal anonymity.
- **Window Bumping:** If a credential is issued or re-issued close to an upcoming boundary (specifically, within the configured `re_issuance_window_days`), the logic automatically rolls the expiration forward by one full epoch. This elegantly ensures holders are never issued a credential that is already legally "about to expire", while naturally facilitating early/on-time re-issuances without requiring inspection of their previous credential.

---

## Module Reference

### Entities

#### `IssuerInstance`

**Module:** `bbs_iss.entities.issuer`

The Issuer is responsible for key generation, nonce-based freshness enforcement, blinded commitment verification, and blind signing.

##### Inner Class: `IssuerInstance.State`

Tracks whether the Issuer is currently processing a request.

| Attribute    | Type           | Description                                           |
|-------------|----------------|-------------------------------------------------------|
| `available` | `bool`         | `True` if the Issuer can accept new requests          |
| `freshness` | `bytes \| None`| The nonce for the current interaction                 |
| `type`      | `RequestType \| None` | The request type that initiated the interaction |

| Method                                     | Description                                   |
|-------------------------------------------|-----------------------------------------------|
| `start_interaction(type, nonce)`          | Marks the Issuer as busy with a given nonce   |
| `end_interaction()`                       | Resets all state fields to idle               |

##### `IssuerInstance` Methods

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `__init__(_private_key_pair=None)` | Optional `bbs.BlsKeyPair` | — | Generates or accepts a BLS12-381 G2 keypair. Exposes the public key as a `PublicKeyBLS` wrapper via `self.public_key`. |
| `set_epoch_size_days(days)` | `int` | — | Sets the default credential expiration duration in days. |
| `set_re_issuance_window_days(days)` | `int` | — | Sets the allowed time window before expiration when re-issuance is permitted. |
| `set_issuer_parameters(params)` | `dict` | — | Sets arbitrary parameters like the issuer's name. |
| `get_configuration()` | — | `str` | Returns a beautifully formatted status string detailing the issuer's current configuration (borders, truncated keys, aligned epoch boundaries). |
| `process_request(request)` | `Request` | `FreshnessUpdateResponse \| ForwardVCResponse \| bool` | Main dispatch method. Routes `ISSUANCE` and `RE_ISSUANCE` requests to `freshness_response()`, `BLIND_SIGN` requests to `issue_vc_blind()`, `FORWARD_VP_AND_CMT` to `re_issue_vc()`, and registry responses to internal state handlers. Returns `True` if a registry interaction succeeded. |
| `register_issuer(initial_bitstring)` | `str` | `RegisterIssuerDetailsRequest` | Initiates the registration of the issuer's public key and configuration with the Registry. |
| `update_issuer_details(new_bitstring)` | `str` | `UpdateIssuerDetailsRequest` | Updates the registered metadata (e.g., rotating the revocation bitstring). |
| `freshness_response(request_type)` | `RequestType` | `FreshnessUpdateResponse` | Generates a 32-byte nonce via `utils.gen_nonce()`, transitions to busy state, returns nonce wrapped in a response. |
| `blind_sign(request)` | `BlindSignRequest` | `bytes` | Verifies the blinded commitment proof, then computes a blind BBS+ signature. Raises `ProofValidityError` if the commitment proof fails. |
| `issue_vc_blind(request)` | `BlindSignRequest` | `ForwardVCResponse` | Pre-computes a `VerifiableCredential` from the attribute metadata, appends validity and revocation fields, calculates the `metaHash`, updates it in both the VC and the signing request, calls `blind_sign()`, attaches the signature, and wraps the VC in a `ForwardVCResponse`. |
| `re_issue_vc(request)` | `ForwardVpAndCmtRequest` | `ForwardVCResponse` | Verifies the presentation of the old credential, ensures attributes match the new request, checks re-issuance window limits, verifies the new commitment, computationally revokes the old index, and issues a new VC with updated expiry. |
| `generate_valid_until()` | — | `str` | Calculates the upcoming globally-aligned epoch boundary based on the `baseline_date` and `epoch_size_days`, automatically rolling to the next boundary if the current time falls within the re-issuance window. |
| `generate_revocation_index()` | — | `str` | Generates a revocation index identifier for the credential. |
| `revoke_index(index)` | `str` | — | Marks the given index as revoked (mock implementation). |
| `key_gen()` | — | `bbs.BlsKeyPair` | Generates a BLS12-381 G2 keypair from a random 32-byte seed. |

---

#### `HolderInstance`

**Module:** `bbs_iss.entities.holder`

The Holder initiates credential issuance, builds blinded commitments over private attributes, and verifies the resulting credential.

##### Inner Class: `HolderInstance.State`

Tracks active interaction state including the Issuer's public key, attribute set, and freshness nonce.

| Attribute          | Type                     | Description                                      |
|-------------------|--------------------------|--------------------------------------------------|
| `awaiting`        | `bool`                   | `True` while an interaction is in progress       |
| `freshness`       | `bytes \| None`          | The Issuer's nonce for the current session       |
| `issuer_pub_key`  | `PublicKeyBLS \| None`   | The Issuer's public key                          |
| `attributes`      | `IssuanceAttributes \| None` | The attribute set for this credential        |
| `cred_name`       | `str \| None`            | Name identifier for the credential               |
| `original_request`| `RequestType \| None`    | The request type that started this interaction   |
| `pending_issuer_name`| `str \| None`          | The name of an issuer awaiting registry resolution |

| Method / Property                                     | Description                                    |
|------------------------------------------------------|------------------------------------------------|
| `start_interaction(issuer_pub_key, attributes, cred_name, original_request)` | Sets all state fields, marks as awaiting |
| `add_freshness(nonce)`                               | Stores the freshness nonce                     |
| `end_interaction()`                                  | Clears all state fields                        |
| `blind_sign_request_ready` *(property)*              | `True` when awaiting, original request is `ISSUANCE`, and no freshness yet |
| `unblind_ready` *(property)*                         | `True` when awaiting, original request is `ISSUANCE`, and freshness is present |

##### `HolderInstance` Methods

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `__init__()` | — | — | Initializes empty state, a `credentials` dictionary, and a `public_data_cache`. |
| `process_request(request)` | `Request` | `BlindSignRequest \| ForwardVpAndCmtRequest \| IssuerPublicData \| list[IssuerPublicData] \| VCIssuanceRequest \| bool` | Dispatch method. Routes `FRESHNESS` responses, `FORWARD_VC` storage, and `ISSUER_DETAILS` responses. Handles **Asynchronous Resumption**: if a response completes a pending issuer resolution, it automatically proceeds to the next step of the suspended issuance flow. |
| `issuance_request(issuer_name, attributes, cred_name)` | `str`, `IssuanceAttributes`, `str` | `VCIssuanceRequest \| GetIssuerDetailsRequest` | Cache-first lookup for the issuer. If found, returns `VCIssuanceRequest` immediately. If not found, stores the request parameters in a pending state and returns `GetIssuerDetailsRequest` to trigger resolution. |
| `re_issuance_request(vc_name, always_hidden_keys=None)` | `str`, `list[str]` | `Request` | Prepares attributes from the existing credential for re-issuance, retaining those specified in `always_hidden_keys` as blinded. |
| `blind_sign_request(freshness)` | `bytes` (nonce) | `BlindSignRequest` | Checks `blind_sign_request_ready`, stores the nonce, calls `build_commitment_append_meta()`, and constructs a `BlindSignRequest`. Raises `HolderStateError` if preconditions are not met. |
| `forward_vp_and_cmt_request(freshness)` | `bytes` | `ForwardVpAndCmtRequest` | Builds a new commitment and a Verifiable Presentation of the existing credential using the given nonce. |
| `verify_vc(pub_key=None, vc=None, vc_name=None)` | optional `PublicKeyBLS`, optional `VerifiableCredential`, optional `str` | `bool` | Verifies a VC's BBS+ signature. Accepts either a VC object directly or a credential name to look up in `self.credentials`. Calls `vc.prepare_verification_request()` internally. |
| `unblind_verify_save_vc(vc)` | `VerifiableCredential` | `bool` | Checks `unblind_ready`, unblinds the signature, fills in blinded attribute values in the VC, verifies the signature via `verify_vc()`, stores the credential alongside the issuer public key, clears interaction state, and returns the verification result. Raises `HolderStateError` if preconditions are not met, or `ProofValidityError` if signature verification fails. |
| `build_vp(revealed_keys, nonce, issuer_pub_key=None, vc=None, vc_name=None, always_hidden_keys=None, commitment=None)` | `list[str]`, `bytes`, kwargs | `VerifiablePresentation` | Core ZKP construction logic. Resolves the credential, builds the VP envelope via `from_verifiable_credential()`, tags ProofMessages as `Revealed` or `Hidden`, derives the bound nonce (optionally hashing in a new `commitment`), and runs `bbs.create_proof()`. |
| `present_credential(vp_request, vc_name, always_hidden_keys=None)` | `VPRequest`, `str`, optional `list[str]` | `ForwardVPResponse` | High-level API for responding to a verifier. Checks attribute availability, ensures no conflict with `always_hidden_keys`, delegates to `build_vp()`, and returns the `ForwardVPResponse`. |
| `get_issuer_details(issuer_name)` | `str` | `IssuerPublicData \| GetIssuerDetailsRequest` | Cache-first lookup. Returns metadata immediately on hit, or triggers a registry lookup on miss. |
| `fetch_all_issuer_details()` | — | `BulkGetIssuerDetailsRequest` | Triggers a full synchronization of the local cache with the registry. |

---

#### `VerifierInstance`

**Module:** `bbs_iss.entities.verifier`

The Verifier initiates presentation requests, issues challenge nonces, and cryptographically verifies the resulting zero-knowledge proofs.

##### Inner Class: `VerifierInstance.State`

Tracks whether the Verifier is currently waiting for a presentation.

| Attribute    | Type           | Description                                           |
|-------------|----------------|-------------------------------------------------------|
| `awaiting`  | `bool`         | `True` while waiting for a VP response                |
| `freshness` | `bytes \| None`| The challenge nonce issued to the Holder              |
| `attributes`| `list[str] \| None`| The list of attributes requested                      |
| `type`      | `RequestType \| None` | Tracking the active request type (`VP_REQUEST`) |
| `queued_response`| `ForwardVPResponse \| None`| A VP parked while awaiting issuer resolution |

| Method / Property                               | Description                                    |
|-------------------------------------------------|------------------------------------------------|
| `start_vp_request(nonce, attributes)`           | Sets all state fields, marks as awaiting       |
| `end_interaction()`                             | Clears all state fields, marks as available    |
| `available` *(property)*                        | `True` when not awaiting                       |

##### `VerifierInstance` Methods

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `__init__()` | — | — | Initializes empty state and a `public_data_cache`. |
| `presentation_request(requested_attributes)` | `list[str]` | `VPRequest` | Generates a 32-byte challenge nonce via `gen_nonce()`, saves it to state along with the required attributes, and returns a `VPRequest`. Raises `VerifierStateError` if already busy. |
| `process_request(request)` | `Request` | `tuple \| IssuerPublicData \| list[IssuerPublicData] \| GetIssuerDetailsRequest` | Main dispatch method. Routes `FORWARD_VP` responses to `verify_vp()` and registry responses to the `PublicDataCache`. Implements **Asynchronous Resolution**: if `FORWARD_VP` targets an unknown issuer, it parks the VP in `queued_response` and returns a `GetIssuerDetailsRequest`. It automatically resumes verification once the registry response is processed. |
| `verify_vp(vp, pub_key)` | `VerifiablePresentation`, `PublicKeyBLS` | `tuple[bool, dict \| None, VP]` | Two-phase verification. Phase 1 checks Attribute Completeness against the original `requested_attributes`. Phase 2 reconstructs the bound nonce and runs BBS+ `verify_proof()`. Returns `(is_valid, revealed_attributes, vp_object)`. |
| `get_issuer_details(issuer_name)` | `str` | `IssuerPublicData \| GetIssuerDetailsRequest` | Triggers authoritative metadata lookup. |
| `fetch_all_issuer_details()` | — | `BulkGetIssuerDetailsRequest` | Triggers a full registry sync. |

---

#### `RegistryInstance`

**Module:** `bbs_iss.entities.registry`

A centralized authority that manages `IssuerPublicData` records.

| `process_request(request)` | `Request` | `IssuerDetailsResponse \| BulkIssuerDetailsResponse` | Validates and stores incoming issuer data, or serves requested metadata. |
| `get_status_string()` | — | `str` | Returns a beautifully formatted summary of all registered issuers. |

---

### Interfaces

#### `requests_api`

**Module:** `bbs_iss.interfaces.requests_api`

Contains all request/response classes, key wrappers, and the attribute management model. All objects in this module support standardized serialization (`to_dict`/`to_json`) and human-readable reporting (`get_print_string`).

##### `PublicKeyBLS`

Wrapper around a BLS12-381 G2 public key.

| Attribute | Type    | Description                |
|----------|---------|----------------------------|
| `key`    | `bytes` | The raw public key bytes   |

##### `SigningPublicKey`

Wrapper around a derived BBS+ signing public key.

| Attribute | Type    | Description                        |
|----------|---------|-------------------------------------|
| `key`    | `bytes` | The derived signing public key bytes |

| Method (static) | Parameters | Returns | Description |
|-----------------|-----------|---------|-------------|
| `derive_signing_public_key(public_key, total_messages)` | `PublicKeyBLS`, `int` | `SigningPublicKey` | Derives a BBS+ signing key from a BLS public key for a given message count via `BlsKeyPair.get_bbs_key()`. |

##### `IssuerPublicData`
 
 The authoritative metadata record for an Issuer, stored in the Registry and local caches.
 
 | Attribute | Type | Description |
 |-----------|------|-------------|
 | `issuer_name` | `str` | Unique identifier for the issuer |
 | `public_key` | `PublicKeyBLS` | The issuer's BLS public key |
 | `revocation_bitstring` | `str` | Hex-encoded revocation status vector |
 | `valid_until_weeks` | `int` | Default credential validity duration |
 | `validity_window_days` | `int` | Re-issuance window configuration |
 
 | Method | Parameters | Returns | Description |
 |--------|------------|---------|-------------|
 | `check_revocation_status(bit_index)` | `int` | `bool` | Returns `True` if the credential at the given index is marked as revoked in the bitstring. |
 
 ##### `AttributeType` (Enum)

| Member     | Value | Description        |
|-----------|-------|---------------------|
| `REVEALED`| 1     | Known to the Issuer |
| `HIDDEN`  | 2     | Blinded from the Issuer |

##### `KeyedIndexedMessage`

**Extends:** `bbs.IndexedMessage`

Adds a `key` (attribute name) field to the library's `IndexedMessage`, allowing attributes to carry both a position index and a human-readable label.

| Attribute | Type  | Description         |
|----------|-------|----------------------|
| `index`  | `int` | Position in the attribute vector |
| `message`| `str` | The attribute value  |
| `key`    | `str` | The attribute name   |

##### `IssuanceAttributes`

Manages the full attribute set for a credential issuance, separating revealed from blinded attributes and handling the Pedersen commitment lifecycle.

| Attribute | Type | Description |
|----------|------|-------------|
| `size` | `int` | Total number of attributes (revealed + blinded) |
| `attributes` | `list[KeyedIndexedMessage]` | Revealed attributes |
| `blinded_attributes` | `list[KeyedIndexedMessage]` | Blinded attributes (with real values) |
| `messages_with_blinded_indices` | `list[KeyedIndexedMessage]` | Blinded attribute indices with empty message values (library workaround) |
| `_committed` | `bool` | Whether `build_commitment_append_meta()` has been called |
| `_commitment` | `bytes \| None` | The Pedersen commitment |
| `_blinding_factor` | `bytes \| None` | The blinding factor for unblinding |
| `_proof` | `bytes \| None` | The zero-knowledge proof of correct commitment |

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `append(key, attribute, type)` | `str`, `str`, `AttributeType` | — | Adds an attribute. Automatically assigns the next sequential index. Hidden attributes also generate a corresponding empty-valued entry in `messages_with_blinded_indices`. |
| `build_commitment_append_meta(nonce, public_key)` | `bytes`, `PublicKeyBLS` | — | First appends a `metaHash` placeholder as a revealed attribute via `VerifiableCredential.META_HASH_KEY`. Then derives the signing public key, creates a `CreateBlindedCommitmentRequest`, and stores the resulting commitment, blinding factor, and proof. Raises `NoBlindedAttributes` if no hidden attributes exist. |
| `get_commitment()` | — | `bytes` | Returns the commitment. Raises `AttributesNotCommitted` if not yet built. |
| `get_blinding_factor()` | — | `bytes` | Returns the blinding factor. Raises `AttributesNotCommitted` if not yet built. |
| `get_revealed_attributes()` | — | `list[KeyedIndexedMessage]` | Returns revealed attributes. Raises `NoRevealedAttributes` if empty. |
| `get_proof()` | — | `bytes` | Returns the commitment proof. Raises `AttributesNotCommitted` if not yet built. |
| `get_messages_with_blinded_indices()` | — | `list[KeyedIndexedMessage]` | Returns the blinded index entries. |
| `attributes_to_list()` | — | `list[str]` | Reconstructs a positionally-ordered list of all attribute values (revealed and blinded) for BBS+ verification. |

##### Request / Response Classes

All request and response objects inherit from `Request` and carry a `request_type: RequestType` discriminator.

| Class | `RequestType` | Key Attributes | Description |
|-------|--------------|----------------|-------------|
| `Request` | *(base)* | `request_type` | Abstract base for all protocol messages. |
| `VCIssuanceRequest` | `ISSUANCE` | *(none)* | Signals the start of an issuance interaction. |
| `FreshnessUpdateResponse` | `FRESHNESS` | `nonce: bytes` | Carries the Issuer's freshness nonce. |
| `BlindSignRequest` | `BLIND_SIGN` | `revealed_attributes`, `commitment`, `total_messages`, `proof`, `messages_with_blinded_indices` | Constructed directly from an `IssuanceAttributes` instance. Carries all data the Issuer needs to verify the commitment and compute a blind signature. |
| `ForwardVCResponse` | `FORWARD_VC` | `vc: VerifiableCredential` | Carries the issued credential back to the Holder. |
| `ForwardVpAndCmtRequest` | `FORWARD_VP_AND_CMT` | `vp`, `commitment`, `proof`, `revealed_attributes` | Used during re-issuance to present an existing credential alongside a blinded commitment for the new one. |
| `RegisterIssuerDetailsRequest`| `REGISTER_ISSUER_DETAILS` | `issuer_name`, `issuer_data` | Used by Issuers to announce their metadata to the Registry. |
| `UpdateIssuerDetailsRequest`  | `UPDATE_ISSUER_DETAILS` | `issuer_name`, `issuer_data` | Used by Issuers to update their registered metadata. |
| `GetIssuerDetailsRequest`     | `GET_ISSUER_DETAILS` | `issuer_name` | Dispatched by Entities to lookup an Issuer's metadata. |
| `IssuerDetailsResponse`       | `ISSUER_DETAILS_RESPONSE` | `issuer_data` | Carries a single issuer's metadata from the Registry. |
| `BulkGetIssuerDetailsRequest` | `BULK_ISSUER_DETAILS_REQUEST` | *(none)* | Dispatched by Entities to fetch all registered issuers. |
| `BulkIssuerDetailsResponse`   | `BULK_ISSUER_DETAILS_RESPONSE` | `issuers_data: list` | Carries the complete registry state. |
| `VPRequest` | `VP_REQUEST` | `requested_attributes: list[str]`, `nonce: bytes` | Dispatched by Verifier to request specific attributes and bind the proof to a challenge. |
| `ForwardVPResponse` | `FORWARD_VP` | `vp: VerifiablePresentation`, `pub_key: PublicKeyBLS` | Carries the ZKP and revealed attributes back to the Verifier. |

##### `RequestType` (Enum)

| Member | Value | Used In Protocol |
|--------|-------|:---:|
| `ISSUANCE` | 1 | ✓ |
| `RE_ISSUANCE` | 2 | ✓ |
| `BLIND_SIGN` | 3 | ✓ |
| `BLIND_RE_SIGN` | 4 | — |
| `FRESHNESS` | 5 | ✓ |
| `VP_REQUEST` | 6 | ✓ |
| `FORWARD_VC` | 7 | ✓ |
| `FORWARD_VP` | 8 | ✓ |
| `VRF_ACKNOWLEDGE` | 9 | — |
| `ERROR` | 10 | — |
| `FORWARD_VP_AND_CMT` | 11 | ✓ |
| `REGISTER_ISSUER_DETAILS` | 12 | ✓ |
| `UPDATE_ISSUER_DETAILS` | 13 | ✓ |
| `GET_ISSUER_DETAILS` | 14 | ✓ |
| `ISSUER_DETAILS_RESPONSE` | 15 | ✓ |
| `BULK_ISSUER_DETAILS_REQUEST` | 16 | ✓ |
| `BULK_ISSUER_DETAILS_RESPONSE` | 17 | ✓ |

---

#### `credential`

**Module:** `bbs_iss.interfaces.credential`

##### `VerifiableCredential`

A mock W3C Verifiable Credential for BBS+ signatures.

##### Class Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_CONTEXT` | `["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/bbs/v1"]` | Default JSON-LD `@context` |
| `DEFAULT_TYPE` | `["VerifiableCredential"]` | Base credential type (extended with `"MockCredential"` at instantiation) |
| `META_HASH_KEY` | `"metaHash"` | Key used in `credential_subject` for the metadata hash |
| `META_HASH_PLACEHOLDER` | `"PLACE-HOLDER-METAHASH"` | Placeholder value before `metaHash` is computed |

##### Instance Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `context` | `list[str]` | JSON-LD `@context` (defaults to `DEFAULT_CONTEXT`) |
| `type` | `list[str]` | Credential types (defaults to `["VerifiableCredential", "MockCredential"]`) |
| `issuer` | `str` | Issuer identifier |
| `credential_subject` | `dict[str, Any]` | Key-value map of credential attributes |
| `proof` | `bytes \| None` | The BBS+ signature bytes |

##### Methods

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `to_dict()` | — | `dict` | Serializes to a W3C-style dictionary. Proof is hex-encoded. |
| `from_dict(data)` *(classmethod)* | `dict` | `VerifiableCredential` | Deserializes from a dictionary. |
| `to_json(indent=4)` | `int` | `str` | JSON serialization. |
| `from_json(json_str)` *(classmethod)* | `str` | `VerifiableCredential` | JSON deserialization. |
| `parse_sorted_keyed_indexed_messages(messages)` *(static)* | `list[KeyedIndexedMessage]` | `dict[str, str]` | Converts a list of `KeyedIndexedMessage` objects into a `{key: message}` dictionary, sorted by index. |
| `prepare_verification_request(pub_key)` | `PublicKeyBLS` | `bbs.VerifyRequest` | Builds a BBS+ `VerifyRequest` by copying the credential subject, re-computing the `metaHash` via `normalize_meta_fields()`, and assembling the message list with the issuer's public key and stored signature. |
| `normalize_meta_fields()` | — | `str` | Deterministically hashes the credential's metadata fields (`@context`, `type`, `issuer`, `credentialSubject` keys in insertion order, `proof` label) via incremental BLAKE2b (32-byte digest). Key order is preserved (not sorted) so that reordering attributes produces a different hash — this is required for BBS message-index binding. Returns the hex digest. |

##### `VerifiablePresentation`

A W3C-style Verifiable Presentation envelope that carries the ZKP proof and a stripped-down `VerifiableCredential` containing only revealed attributes.

##### Methods

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `from_verifiable_credential(credential, revealed_attributes)` | `VerifiableCredential`, `list[str]` | — | Populates the VP envelope using a subset of the original VC's attributes. |
| `add_proof(proof)` | `bytes` | — | Sets the ZKP bytes on the embedded VC. |
| `normalize_meta_fields()` | — | `str` | Hashes the VP envelope and the embedded credential envelope (excluding variable proof values and the values of the revealed attributes, as they are protected by the ZKP). Provides deterministic data binding using BLAKE2b. |
| `build_bound_nonce(nonce, commitment=None)` | `bytes`, optional `bytes` | `bytes` | Produces an *effective nonce* by hashing the verifier's original challenge nonce with the output of `normalize_meta_fields()` (and optionally an embedded `commitment` for re-issuance flows). This cryptographically binds the metadata envelope and new commitment to the specific presentation session. |
| `prepare_verification_request(pub_key, nonce, commitment=None)` | `PublicKeyBLS`, `bytes`, optional `bytes` | `bbs.VerifyProofRequest` | Reconstructs the bound nonce and extracts revealed message values in order, producing the final request needed for the Verifier to execute `bbs.verify_proof`. |
| Serialization | `to_dict()`, `from_dict()`, `to_json()`, `from_json()` | — | Converts between python objects, dictionaries, and JSON strings, maintaining proper hex encoding of the ZKP proof. |

---

### Exceptions

**Module:** `bbs_iss.exceptions.exceptions`

All exceptions use the pattern `def __init__(self, message="<default>")` unless otherwise noted.

| Exception | Default Message | Typical Trigger |
|-----------|----------------|-----------------|
| `AttributesNotCommitted` | "Attributes not committed" | Accessing commitment data before `build_commitment_append_meta()` |
| `NoBlindedAttributes` | "No blinded attributes" | Calling `build_commitment_append_meta()` with no hidden attributes |
| `NoRevealedAttributes` | "No revealed attributes" | Calling `get_revealed_attributes()` when none exist |
| `IssuerNotAvailable` | "Issuer is processing another request" | Sending `ISSUANCE` while Issuer is busy |
| `HolderNotInInteraction` | "Holder is not in an active interaction" | Calling `process_request()` without a prior `issuance_request()` |
| `FreshnessValueError` | "Invalid freshness value" | Blinded commitment verification failure |
| `HolderStateError` | "Invalid holder state" | State precondition not met in Holder. Accepts an optional `state` keyword argument; when provided, the error message includes a dump of all state attributes for debugging. |
| `ProofValidityError` | "Invalid proof" | Raised on failure of BBS+ signature verification after unblinding on the Holder side, or failure of blinded commitment proof verification on the Issuer side. |
| `VerifierNotInInteraction`| "Verifier is not in an active interaction" | Calling `process_request()` in the Verifier without a prior `presentation_request()` |
| `VerifierStateError` | "Invalid verifier state" | State precondition not met in Verifier (e.g. issuing two VP requests sequentially). Accepts an optional `state` keyword argument. |
| `UnregisteredIssuerError` | "Issuer not found in registry" | Dispatched by Holder if a registry resolution returns no data for a pending issuance. |
| `IssuerNotFoundInCacheError`| "Issuer not found in local cache" | Attempting to access metadata directly without checking the registry. |

---

### Utils

**Module:** `bbs_iss.utils.utils`

| Function | Parameters | Returns | Description |
|----------|-----------|---------|-------------|
| `gen_link_secret(size=32)` | `int` | `str` | Generates a hex-encoded random link secret of the given byte size via `os.urandom`. |
| `gen_nonce()` | — | `bytes` | Returns 32 bytes of OS randomness. Used by `IssuerInstance.freshness_response()`. |

---

#### `PublicDataCache`

**Module:** `bbs_iss.utils.cache`

An in-memory manager for `IssuerPublicData` records, used by Holders and Verifiers to avoid redundant registry lookups.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `update(issuer_name, data)` | `str`, `IssuerPublicData` | — | Upserts a record into the cache with a current UTC timestamp. |
| `get(issuer_name)` | `str` | `IssuerPublicData \| None` | Returns the metadata if present, otherwise `None`. |
| `get_entry(issuer_name)` | `str` | `CacheEntry \| None` | Returns the full `CacheEntry` (including metadata and `obtained_at` timestamp). |
| `clear()` | — | — | Purges all cached records. |
| `get_cache_info()` | — | `str` | Returns a beautifully formatted string summary of all cached issuers. |
| `check_bit_index(issuer, bit_index)` | `str`, `int` | `bool` | High-level revocation check. Retrieves the issuer from the cache and checks the specified bit index. Raises `IssuerNotFoundInCacheError` if the issuer is not present. |

---

### Serialization & Debugging

To facilitate real-world data exchange across various mediums (HTTP, QR scans, etc.), all request and response objects implement standardized serialization:

- **JSON/Dict Support**: Every `Request` subclass supports `to_dict()`, `from_dict()`, `to_json()`, and `from_json()`. Binary fields (keys, proofs, commitments) are automatically hex-encoded.
- **Polymorphic Reconstruction**: The base `Request` class includes a factory `from_dict()` method. This enables the system to receive a generic JSON blob and automatically reconstruct the correct specific subclass (e.g., `BlindSignRequest`) based on the internal `request_type` discriminator.
- **Rich Pretty-Printing**: Each request class implements `get_print_string()`, providing a human-readable, bordered summary of its contents. Complex nested structures like `VerifiableCredential` and `VerifiablePresentation` are automatically pretty-printed using formatted JSON.

---

## Usage Example

## Usage Example

The following code demonstrates a full round-trip from blind issuance to selective disclosure via zero-knowledge proof.

```python
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
import bbs_iss.interfaces.requests_api as api
import bbs_iss.utils.utils as utils

# ─── 1. Setup & Authority Registration ──────────────────────────────
issuer = IssuerInstance()
issuer.issuer_parameters = {"issuer": "University-Authority"}
registry = RegistryInstance()
holder = HolderInstance()
verifier = VerifierInstance()

# Issuer announces metadata to the Registry
reg_req = issuer.register_issuer()
reg_resp = registry.process_request(reg_req)
issuer.process_request(reg_resp)

# ─── 2. Define Attributes & ISSUANCE ────────────────────────────────
attributes = api.IssuanceAttributes()
attributes.append("secret", utils.gen_link_secret(), api.AttributeType.HIDDEN)
attributes.append("degree", "Bachelor of Cryptography", api.AttributeType.REVEALED)

# Holder initiates issuance using issuer name (authoritative resolution)
issuer_name = "University-Authority"
init_request = holder.issuance_request(issuer_name, attributes, "degree-cred")

if isinstance(init_request, api.GetIssuerDetailsRequest):
    # Proactive resolution triggered
    reg_resp = registry.process_request(init_request)
    init_request = holder.process_request(reg_resp)

freshness_response = issuer.process_request(init_request)
blind_sign_request = holder.process_request(freshness_response)
forward_vc_response = issuer.process_request(blind_sign_request)

# Holder unblinds and saves credential
is_vc_valid = holder.process_request(forward_vc_response)
print(f"Credential issuance success: {is_vc_valid}")

# ─── 3. REGISTRY LOOKUP & PRESENTATION ──────────────────────────────
# Verifier needs the issuer's public key but doesn't have it in cache
# It performs an authoritative lookup via the Registry
issuer_name = "University-Authority"
lookup_req = verifier.get_issuer_details(issuer_name)

if isinstance(lookup_req, api.GetIssuerDetailsRequest):
    # Cache miss - synchronize with registry
    lookup_resp = registry.process_request(lookup_req)
    issuer_metadata = verifier.process_request(lookup_resp)
else:
    # Cache hit
    issuer_metadata = lookup_req

# Now the verifier has the public key in its local cache
print(verifier.public_data_cache.get_cache_info())

# Verifier requests proof
vp_request = verifier.presentation_request(requested_attributes=["degree"])
vp_response = holder.present_credential(vp_request, "degree-cred", always_hidden_keys=["secret"])

# Verification against cached authoritative key
is_vp_valid, revealed_attrs, _ = verifier.process_request(vp_response)
print(f"ZKP Validation: {is_vp_valid} | Data: {revealed_attrs}")

# ─── 4. RE-ISSUANCE ──────────────────────────────────────────────────
# Holder initiated renewal
re_init_req = holder.re_issuance_request("degree-cred", always_hidden_keys=["secret"])
re_freshness = issuer.process_request(re_init_req)
vp_and_cmt_req = holder.process_request(re_freshness)
re_forward_vc = issuer.process_request(vp_and_cmt_req)

is_reissued_valid = holder.process_request(re_forward_vc)
print(f"Credential re-issuance success: {is_reissued_valid}")
```

---

## Known Issues & Library Fixes

The `ursa_bbs_signatures` library contains several bugs that required local patches. See [`BBS_LIBRARY_FIX.md`](BBS_LIBRARY_FIX.md) for the full list of fixes applied to the library.

A security note on potential data leakage during blinded commitment verification is documented in [`BLINDED_COMMITMENT_NOTE.md`](BLINDED_COMMITMENT_NOTE.md).

---

## Acknowledgments

This prototype utilizes the Python wrapper and `libbbs.so` components from the [ffi-bbs-signatures](https://github.com/mattrglobal/ffi-bbs-signatures) repository (originally maintained by `mattrglobal` / Hyperledger Aries Contributors) for its underlying cryptographic operations. 

A locally patched version of this library is vendored into this project as a Git Submodule under `vendor/ffi-bbs-signatures` to resolve critical execution bugs during blind signing and verify flows. All original rights and open-source licenses (Apache 2.0 / MIT) associated with the `ffi-bbs-signatures` repository remain explicitly applicable to the submodule source.
