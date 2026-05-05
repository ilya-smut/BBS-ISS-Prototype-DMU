# BBS-ISS-Prototype-DMU

A Python prototype implementing **BBS+ blind issuance and selective disclosure** between an Issuer, a Holder, and a Verifier, using the [`ursa_bbs_signatures`](https://pypi.org/project/ursa-bbs-signatures/) library. The project demonstrates a complete credential lifecycle: a multi-round issuance protocol with blinded commitments, followed by Verifiable Presentation (VP) generation with zero-knowledge proof verification.

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
│       │   └── verifier.py         # VerifierInstance class
│       ├── interfaces/             # Shared data types and protocol messages
│       │   ├── __init__.py
│       │   ├── requests_api.py     # Request/response classes and data models
│       │   └── credential.py       # VerifiableCredential and VerifiablePresentation classes
│       ├── exceptions/             # Custom exception hierarchy
│       │   └── exceptions.py       # All project exceptions
│       └── utils/                  # Utility functions
│           └── utils.py            # Nonce generation, link secret generation
├── testing/
│   ├── unit/                       # Pytest comprehensive unit test suite
│   │   ├── test_attributes.py
│   │   ├── test_credential.py
│   │   ├── test_issuance_flow.py
│   │   ├── test_participant_states.py
│   │   ├── test_verifiable_presentation.py
│   │   └── test_vp_flow.py         # Tests for Verifiable Presentation API
│   ├── vp-test.py                  # End-to-end issuance and presentation test script
│   ├── issuance-test.py            # Issuance test script
│   ├── playground.ipynb            # Interactive end-to-end issuance notebook
│   └── test-notebook.ipynb         # Test notebook
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
  ├── unblind signature                          │
  ├── verify signature                           │
  └── store credential                           │
```

**Step 1 — Issuance Request:** The Holder initiates the protocol by sending a `VCIssuanceRequest`. Internally, the Holder stores the public key, attributes, and credential name in its local state.

**Step 2 — Freshness Response:** The Issuer generates a random 32-byte nonce and returns it as a `FreshnessUpdateResponse`. This value binds the commitment to a specific session, preventing replay attacks.

**Step 3 — Blind Sign Request:** The Holder builds a Pedersen commitment over its blinded attributes using the Issuer's nonce and public key. This step also appends a `metaHash` revealed attribute that deterministically hashes the credential's metadata fields (context, type, issuer, subject keys). It sends a `BlindSignRequest` containing the commitment, a zero-knowledge proof of correct commitment construction, the revealed attributes (including `metaHash`), and their indices.

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
| `process_request(request)` | `Request` | `FreshnessUpdateResponse \| ForwardVCResponse` | Main dispatch method. Routes `ISSUANCE` requests to `freshness_response()` and `BLIND_SIGN` requests to `issue_vc_blind()`. Raises `IssuerNotAvailable` if busy. |
| `freshness_response()` | — | `FreshnessUpdateResponse` | Generates a 32-byte nonce via `utils.gen_nonce()`, transitions to busy state, returns nonce wrapped in a response. |
| `blind_sign(request)` | `BlindSignRequest` | `bytes` | Verifies the blinded commitment proof, then computes a blind BBS+ signature. Raises `ProofValidityError` if the commitment proof fails. |
| `issue_vc_blind(request)` | `BlindSignRequest` | `ForwardVCResponse` | Pre-computes a `VerifiableCredential` from the attribute metadata, calculates the `metaHash` via `normalize_meta_fields()`, updates it in both the VC and the signing request, calls `blind_sign()`, attaches the signature, and wraps the VC in a `ForwardVCResponse`. |
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
| `__init__()` | — | — | Initializes empty state and a `credentials` dictionary mapping names to `(VerifiableCredential, PublicKeyBLS)` tuples. |
| `process_request(request)` | `Request` | `BlindSignRequest \| bool` | Dispatch method. Routes `FRESHNESS` responses to `blind_sign_request()` and `FORWARD_VC` responses to `unblind_verify_save_vc()`. Raises `HolderNotInInteraction` if no active interaction. |
| `issuance_request(issuer_pub_key, attributes, cred_name)` | `PublicKeyBLS`, `IssuanceAttributes`, `str` | `VCIssuanceRequest` | Initializes the Holder's interaction state and returns an issuance request. |
| `blind_sign_request(freshness)` | `bytes` (nonce) | `BlindSignRequest` | Checks `blind_sign_request_ready`, stores the nonce, calls `build_commitment_append_meta()` (which also appends the `metaHash` placeholder attribute), and constructs a `BlindSignRequest`. Raises `HolderStateError` if preconditions are not met. |
| `verify_vc(pub_key=None, vc=None, vc_name=None)` | optional `PublicKeyBLS`, optional `VerifiableCredential`, optional `str` | `bool` | Verifies a VC's BBS+ signature. Accepts either a VC object directly or a credential name to look up in `self.credentials`. Calls `vc.prepare_verification_request()` internally. |
| `unblind_verify_save_vc(vc)` | `VerifiableCredential` | `bool` | Checks `unblind_ready`, unblinds the signature, fills in blinded attribute values in the VC, verifies the signature via `verify_vc()`, stores the credential alongside the issuer public key, clears interaction state, and returns the verification result. Raises `HolderStateError` if preconditions are not met, or `ProofValidityError` if signature verification fails. |
| `build_vp(revealed_keys, nonce, issuer_pub_key=None, vc=None, vc_name=None, always_hidden_keys=None)` | `list[str]`, `bytes`, kwargs | `VerifiablePresentation` | Core ZKP construction logic. Resolves the credential, builds the VP envelope via `from_verifiable_credential()`, tags ProofMessages as `Revealed` or `Hidden`, derives the bound nonce via `vp.build_bound_nonce()`, and runs `bbs.create_proof()`. |
| `present_credential(vp_request, vc_name, always_hidden_keys=None)` | `VPRequest`, `str`, optional `list[str]` | `ForwardVPResponse` | High-level API for responding to a verifier. Checks attribute availability, ensures no conflict with `always_hidden_keys`, delegates to `build_vp()`, and returns the `ForwardVPResponse`. |

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

| Method / Property                               | Description                                    |
|-------------------------------------------------|------------------------------------------------|
| `start_vp_request(nonce, attributes)`           | Sets all state fields, marks as awaiting       |
| `end_interaction()`                             | Clears all state fields, marks as available    |
| `available` *(property)*                        | `True` when not awaiting                       |

##### `VerifierInstance` Methods

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `__init__()` | — | — | Initializes empty state. |
| `presentation_request(requested_attributes)` | `list[str]` | `VPRequest` | Generates a 32-byte challenge nonce via `gen_nonce()`, saves it to state along with the required attributes, and returns a `VPRequest`. Raises `VerifierStateError` if already busy. |
| `process_request(request)` | `Request` | `tuple` | Main dispatch method. Routes `FORWARD_VP` responses to `verify_vp()`. Raises `VerifierNotInInteraction` if no request is pending. |
| `verify_vp(vp, pub_key)` | `VerifiablePresentation`, `PublicKeyBLS` | `tuple[bool, dict \| None, VP]` | Two-phase verification. Phase 1 checks Attribute Completeness against the original `requested_attributes`. Phase 2 reconstructs the bound nonce and runs BBS+ `verify_proof()`. Returns `(is_valid, revealed_attributes, vp_object)`. |

---

### Interfaces

#### `requests_api`

**Module:** `bbs_iss.interfaces.requests_api`

Contains all request/response classes, key wrappers, and the attribute management model.

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
| `VPRequest` | `VP_REQUEST` | `requested_attributes: list[str]`, `nonce: bytes` | Dispatched by Verifier to request specific attributes and bind the proof to a challenge. |
| `ForwardVPResponse` | `FORWARD_VP` | `vp: VerifiablePresentation`, `pub_key: PublicKeyBLS` | Carries the ZKP and revealed attributes back to the Verifier. |

##### `RequestType` (Enum)

| Member | Value | Used In Protocol |
|--------|-------|:---:|
| `ISSUANCE` | 1 | ✓ |
| `RE_ISSUANCE` | 2 | — |
| `BLIND_SIGN` | 3 | ✓ |
| `BLIND_RE_SIGN` | 4 | — |
| `FRESHNESS` | 5 | ✓ |
| `VP_REQUEST` | 6 | ✓ |
| `FORWARD_VC` | 7 | ✓ |
| `FORWARD_VP` | 8 | ✓ |
| `VRF_ACKNOWLEDGE` | 9 | — |
| `ERROR` | 10 | — |

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
| `build_bound_nonce(nonce)` | `bytes` | `bytes` | Produces an *effective nonce* by hashing the verifier's original challenge nonce with the output of `normalize_meta_fields()`. This cryptographically binds the metadata envelope to the specific presentation session. |
| `prepare_verification_request(pub_key, nonce)` | `PublicKeyBLS`, `bytes` | `bbs.VerifyProofRequest` | Reconstructs the bound nonce and extracts revealed message values in order, producing the final request needed for the Verifier to execute `bbs.verify_proof`. |
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

---

### Utils

**Module:** `bbs_iss.utils.utils`

| Function | Parameters | Returns | Description |
|----------|-----------|---------|-------------|
| `gen_link_secret(size=32)` | `int` | `str` | Generates a hex-encoded random link secret of the given byte size via `os.urandom`. |
| `gen_nonce()` | — | `bytes` | Returns 32 bytes of OS randomness. Used by `IssuerInstance.freshness_response()`. |

---

## Usage Example

## Usage Example

The following code demonstrates a full round-trip from blind issuance to selective disclosure via zero-knowledge proof.

```python
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
import bbs_iss.interfaces.requests_api as api
import bbs_iss.utils.utils as utils

# ─── 1. Setup & Key Generation ───────────────────────────────────────
issuer = IssuerInstance()
holder = HolderInstance()
verifier = VerifierInstance()

# ─── 2. Define Attributes for Issuance ───────────────────────────────
attributes = api.IssuanceAttributes()
attributes.append("secret", utils.gen_nonce(), api.AttributeType.HIDDEN)
attributes.append("not_secret", "very not secret", api.AttributeType.REVEALED)
attributes.append("name", "Alice", api.AttributeType.REVEALED)
attributes.append("studentId", "S-001", api.AttributeType.REVEALED)

# ─── 3. ISSUANCE FLOW ────────────────────────────────────────────────
# Holder initiates issuance
init_request = holder.issuance_request(
    issuer_pub_key=issuer.public_key, 
    attributes=attributes, 
    cred_name="test-cred"
)

# Issuer provides freshness challenge
freshness_response = issuer.process_request(init_request)

# Holder builds blinded commitment and proof
blind_sign_request = holder.process_request(freshness_response)

# Issuer verifies commitment and blind-signs the credential
forward_vc_response = issuer.process_request(blind_sign_request)

# Holder unblinds signature and saves valid credential
is_vc_valid = holder.process_request(forward_vc_response)
print(f"Credential issuance success: {is_vc_valid}")

# ─── 4. PRESENTATION FLOW ────────────────────────────────────────────
# Verifier requests specific attributes with a challenge nonce
vp_request = verifier.presentation_request(
    requested_attributes=["studentId", "name"]
)

# Holder builds zero-knowledge proof of requested attributes
# Ensures "secret" is never disclosed even if requested
vp_response = holder.present_credential(
    vp_request=vp_request, 
    vc_name="test-cred", 
    always_hidden_keys=["secret"]
)

# Verifier confirms completeness and validates ZKP against bound nonce
is_vp_valid, revealed_attrs, vp_obj = verifier.process_request(vp_response)

print(f"Presentation validation success: {is_vp_valid}")
print(f"Revealed Attributes: {revealed_attrs}")
# Output: {'name': 'Alice', 'studentId': 'S-001'}
```

---

## Known Issues & Library Fixes

The `ursa_bbs_signatures` library contains several bugs that required local patches. See [`BBS_LIBRARY_FIX.md`](BBS_LIBRARY_FIX.md) for the full list of fixes applied to the library.

A security note on potential data leakage during blinded commitment verification is documented in [`BLINDED_COMMITMENT_NOTE.md`](BLINDED_COMMITMENT_NOTE.md).

---

## Acknowledgments

This prototype utilizes the Python wrapper and `libbbs.so` components from the [ffi-bbs-signatures](https://github.com/mattrglobal/ffi-bbs-signatures) repository (originally maintained by `mattrglobal` / Hyperledger Aries Contributors) for its underlying cryptographic operations. 

A locally patched version of this library is vendored into this project as a Git Submodule under `vendor/ffi-bbs-signatures` to resolve critical execution bugs during blind signing and verify flows. All original rights and open-source licenses (Apache 2.0 / MIT) associated with the `ffi-bbs-signatures` repository remain explicitly applicable to the submodule source.
