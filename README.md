# BBS-ISS-Prototype-DMU

A Python prototype implementing **BBS+ blind issuance** between an Issuer and a Holder, using the [`ursa_bbs_signatures`](https://pypi.org/project/ursa-bbs-signatures/) library. The project demonstrates a multi-round credential issuance protocol with blinded commitments, selective disclosure, and zero-knowledge proof verification.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Protocol Overview](#protocol-overview)
- [Module Reference](#module-reference)
  - [Entities](#entities)
    - [IssuerInstance](#issuerinstance)
    - [HolderInstance](#holderinstance)
  - [Interfaces](#interfaces)
    - [requests\_api](#requests_api)
    - [credential](#credential)
    - [exceptions](#exceptions)
- [Usage Example](#usage-example)
- [Known Issues & Library Fixes](#known-issues--library-fixes)

---

## Prerequisites

- Python ≥ 3.10
- `ursa-bbs-signatures` ≥ 1.0.1

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd BBS-ISS-Prototype-DMU

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the package in editable mode
pip install -e .
```

---

## Project Structure

```
BBS-ISS-Prototype-DMU/
├── pyproject.toml                  # Package configuration
├── README.md                       # This file
├── BBS_LIBRARY_FIX.md              # Documentation of ursa_bbs_signatures bug fixes
├── BLINDED_COMMITMENT_NOTE.md      # Security note on blinded index data leakage
├── src/
│   └── bbs_iss/                    # Main package
│       ├── __init__.py
│       ├── entities/               # Protocol participants
│       │   ├── __init__.py
│       │   ├── issuer.py           # IssuerInstance class
│       │   └── holder.py           # HolderInstance class
│       └── interfaces/             # Shared data types and protocol messages
│           ├── __init__.py
│           ├── requests_api.py     # Request/response classes and data models
│           ├── credential.py       # VerifiableCredential class
│           └── exceptions.py       # Custom exception hierarchy
├── examples/
│   ├── blind_sign_test.py          # Standalone blind signing demo
│   └── vp.py                       # Verifiable presentation + QR code demo
├── testing/
│   └── playground.ipynb            # Interactive end-to-end issuance notebook
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
  │                                              │
  │<─── 4. ForwardVCResponse (VC w/ blind sig) ──│
  │                                              │
  ├── unblind signature                          │
  ├── verify signature                           │
  └── store credential                           │
```

**Step 1 — Issuance Request:** The Holder initiates the protocol by sending a `VCIssuanceRequest`. Internally, the Holder stores the public key, attributes, and credential name in its local state.

**Step 2 — Freshness Response:** The Issuer generates a random 32-byte nonce and returns it as a `FreshnessUpdateResponse`. This value binds the commitment to a specific session, preventing replay attacks.

**Step 3 — Blind Sign Request:** The Holder builds a Pedersen commitment over its blinded attributes using the Issuer's nonce and public key. It sends a `BlindSignRequest` containing the commitment, a zero-knowledge proof of correct commitment construction, the revealed attributes, and their indices.

**Step 4 — Forward VC Response:** The Issuer first verifies the blinded commitment proof. If valid, it computes a blind BBS+ signature over the commitment and the revealed attributes, wraps it in a `VerifiableCredential`, and returns it as a `ForwardVCResponse`.

The Holder then unblinds the signature using its stored blinding factor and verifies it against the full attribute set.

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
| `process_request(request)` | `Request` | `FreshnessUpdateResponse \| ForwardVCResponse` | Main dispatch method. Routes `ISSUANCE` requests to `freshness_response()` and `BLIND_SIGN` requests to `issue_vc_blind()`. |
| `freshness_response()` | — | `FreshnessUpdateResponse` | Generates a 32-byte nonce, transitions to busy state, returns nonce wrapped in a response. |
| `blind_sign(request)` | `BlindSignRequest` | `bytes` | Verifies the blinded commitment proof, then computes a blind BBS+ signature. Raises `FreshnessValueError` if the commitment proof fails. |
| `issue_vc_blind(request)` | `BlindSignRequest` | `ForwardVCResponse` | Calls `blind_sign()`, constructs a `VerifiableCredential` from the signature and attribute metadata, wraps it in a `ForwardVCResponse`. |
| `key_gen()` | — | `bbs.BlsKeyPair` | Generates a BLS12-381 G2 keypair from a random 32-byte seed. |
| `gen_nonce()` *(static)* | — | `bytes` | Returns 32 bytes of OS randomness. |

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

| Method                                            | Description                                    |
|--------------------------------------------------|------------------------------------------------|
| `start_interaction(issuer_pub_key, attributes, cred_name, original_request)` | Sets all state fields, marks as awaiting |
| `add_freshness(nonce)`                           | Stores the freshness nonce                     |
| `end_interaction()`                              | Clears all state fields                        |

##### `HolderInstance` Methods

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `__init__()` | — | — | Initializes empty state and a `credentials` dictionary. |
| `process_request(request)` | `Request` | `BlindSignRequest \| bool` | Dispatch method. Routes `FRESHNESS` responses to `blind_sign_request()` and `FORWARD_VC` responses to `unblind_and_verify()`. Raises `HolderNotInInteraction` if no active interaction. |
| `issuance_request(issuer_pub_key, attributes, cred_name)` | `PublicKeyBLS`, `IssuanceAttributes`, `str` | `VCIssuanceRequest` | Initializes the Holder's interaction state and returns an issuance request. |
| `blind_sign_request(freshness)` | `bytes` (nonce) | `BlindSignRequest` | Stores the nonce, builds a Pedersen commitment over the blinded attributes (via `IssuanceAttributes.build_commitment()`), and constructs a `BlindSignRequest`. |
| `unblind_and_verify(vc)` | `VerifiableCredential` | `bool` | Unblinds the signature using the stored blinding factor, verifies it against the full attribute list using the Issuer's public key, clears interaction state, and returns the verification result. |

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
|-----------|-------|--------------------|
| `REVEALED`| 1     | Known to the Issuer |
| `HIDDEN`  | 2     | Blinded from the Issuer |

##### `KeyedIndexedMessage`

**Extends:** `bbs.IndexedMessage`

Adds a `key` (attribute name) field to the library's `IndexedMessage`, allowing attributes to carry both a position index and a human-readable label.

| Attribute | Type  | Description         |
|----------|-------|---------------------|
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
| `blinded_indices` | `list[KeyedIndexedMessage]` | Blinded attribute indices with empty message values (library workaround) |
| `_committed` | `bool` | Whether `build_commitment()` has been called |
| `_commitment` | `bytes \| None` | The Pedersen commitment |
| `_blinding_factor` | `bytes \| None` | The blinding factor for unblinding |
| `_proof` | `bytes \| None` | The zero-knowledge proof of correct commitment |

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `append(key, attribute, type)` | `str`, `str`, `AttributeType` | — | Adds an attribute. Automatically assigns the next sequential index. Hidden attributes also generate a corresponding empty-valued entry in `blinded_indices`. |
| `build_commitment(nonce, public_key)` | `bytes`, `PublicKeyBLS` | — | Derives the signing public key, creates a `CreateBlindedCommitmentRequest`, and stores the resulting commitment, blinding factor, and proof. |
| `get_commitment()` | — | `bytes` | Returns the commitment. Raises `AttributesNotCommitted` if not yet built. |
| `get_blinding_factor()` | — | `bytes` | Returns the blinding factor. Raises `AttributesNotCommitted` if not yet built. |
| `get_revealed_attributes()` | — | `list[KeyedIndexedMessage]` | Returns revealed attributes. Raises `NoRevealedAttributes` if empty. |
| `get_proof()` | — | `bytes` | Returns the commitment proof. Raises `AttributesNotCommitted` if not yet built. |
| `get_blinded_indices()` | — | `list[KeyedIndexedMessage]` | Returns the blinded index entries. |
| `attributes_to_list()` | — | `list[str]` | Reconstructs a positionally-ordered list of all attribute values (revealed and blinded) for BBS+ verification. |

##### Request / Response Classes

All request and response objects inherit from `Request` and carry a `request_type: RequestType` discriminator.

| Class | `RequestType` | Key Attributes | Description |
|-------|--------------|----------------|-------------|
| `Request` | *(base)* | `request_type` | Abstract base for all protocol messages. |
| `VCIssuanceRequest` | `ISSUANCE` | *(none)* | Signals the start of an issuance interaction. |
| `FreshnessUpdateResponse` | `FRESHNESS` | `nonce: bytes` | Carries the Issuer's freshness nonce. |
| `BlindSignRequest` | `BLIND_SIGN` | `revealed_attributes`, `commitment`, `total_messages`, `proof`, `blinded_indices` | Carries all data the Issuer needs to verify the commitment and compute a blind signature. |
| `ForwardVCResponse` | `FORWARD_VC` | `vc: VerifiableCredential` | Carries the issued credential back to the Holder. |

##### `RequestType` (Enum)

| Member | Value | Used In Protocol |
|--------|-------|:---:|
| `ISSUANCE` | 1 | ✓ |
| `RE_ISSUANCE` | 2 | — |
| `BLIND_SIGN` | 3 | ✓ |
| `BLIND_RE_SIGN` | 4 | — |
| `FRESHNESS` | 5 | ✓ |
| `VP_REQUEST` | 6 | — |
| `FORWARD_VC` | 7 | ✓ |
| `FORWARD_VP` | 8 | — |
| `VRF_ACKNOWLEDGE` | 9 | — |
| `ERROR` | 10 | — |

---

#### `credential`

**Module:** `bbs_iss.interfaces.credential`

##### `VerifiableCredential`

A mock W3C Verifiable Credential for BBS+ signatures.

| Attribute | Type | Description |
|-----------|------|-------------|
| `context` | `list[str]` | JSON-LD `@context` (defaults to W3C credentials/v1 and BBS security context) |
| `type` | `list[str]` | Credential types (defaults to `["VerifiableCredential", "MockCredential"]`) |
| `issuer` | `str` | Issuer identifier |
| `credential_subject` | `dict[str, Any]` | Key-value map of credential attributes |
| `proof` | `bytes \| None` | The BBS+ signature bytes |

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `to_dict()` | — | `dict` | Serializes to a W3C-style dictionary. Proof is hex-encoded. |
| `from_dict(data)` *(classmethod)* | `dict` | `VerifiableCredential` | Deserializes from a dictionary. |
| `to_json(indent=4)` | `int` | `str` | JSON serialization. |
| `from_json(json_str)` *(classmethod)* | `str` | `VerifiableCredential` | JSON deserialization. |
| `parse_keyed_indexed_messages(messages)` *(static)* | `list[KeyedIndexedMessage]` | `dict[str, str]` | Converts a list of `KeyedIndexedMessage` objects into a `{key: message}` dictionary, sorted by index. |

---

#### `exceptions`

**Module:** `bbs_iss.interfaces.exceptions`

All exceptions use the pattern `def __init__(self, message="<default>")`.

| Exception | Default Message | Typical Trigger |
|-----------|----------------|-----------------|
| `AttributesNotCommitted` | "Attributes not committed" | Accessing commitment data before `build_commitment()` |
| `NoBlindedAttributes` | "No blinded attributes" | Calling `build_commitment()` with no hidden attributes |
| `NoRevealedAttributes` | "No revealed attributes" | Calling `get_revealed_attributes()` when none exist |
| `IssuerNotAvailable` | "Issuer is processing another request" | Sending `ISSUANCE` while Issuer is busy |
| `HolderNotInInteraction` | "Holder is not in an active interaction" | Calling `process_request()` without a prior `issuance_request()` |
| `FreshnessValueError` | "Invalid freshness value" | Blinded commitment verification failure |
| `HolderStateError` | "Invalid holder state" | State precondition not met in Holder |
| `ProofValidityError` | "Invalid proof" | *(Currently unused — reserved for VP verification)* |

---

## Usage Example

```python
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
import bbs_iss.interfaces.requests_api as api

# 1. Setup
issuer = IssuerInstance()
holder = HolderInstance()

# 2. Define attributes
attributes = api.IssuanceAttributes()
attributes.append("name", "Alice", api.AttributeType.REVEALED)
attributes.append("ssn", "123-45-6789", api.AttributeType.HIDDEN)

# 3. Holder → Issuer: Issuance request
init_request = holder.issuance_request(
    issuer_pub_key=issuer.public_key,
    attributes=attributes,
    cred_name="identity-credential"
)

# 4. Issuer → Holder: Freshness nonce
freshness_response = issuer.process_request(init_request)

# 5. Holder → Issuer: Blind sign request (commitment built internally)
blind_sign_request = holder.process_request(freshness_response)

# 6. Issuer → Holder: Signed credential
forward_vc_response = issuer.process_request(blind_sign_request)

# 7. Holder: Unblind and verify
is_valid = holder.process_request(forward_vc_response)
print("Credential valid:", is_valid)  # True
```

---

## Known Issues & Library Fixes

The `ursa_bbs_signatures` library contains several bugs that required local patches. See [`BBS_LIBRARY_FIX.md`](BBS_LIBRARY_FIX.md) for the full list of fixes applied to the library within `.venv`.

A security note on potential data leakage during blinded commitment verification is documented in [`BLINDED_COMMITMENT_NOTE.md`](BLINDED_COMMITMENT_NOTE.md).
