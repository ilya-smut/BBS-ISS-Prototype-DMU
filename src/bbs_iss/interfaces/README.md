# Interfaces — Protocol Data Types & Serialization

This package contains the shared data structures, protocol messages, key wrappers, and credential models used across all entities.

## Architecture

```
interfaces/
├── requests_api.py    # All request/response classes, key wrappers, attribute model
└── credential.py      # VerifiableCredential and VerifiablePresentation models
```

---

## `requests_api.py` — Protocol Messages & Data Model

### Key Wrappers

| Class | Description |
|-------|-------------|
| `PublicKeyBLS` | Wrapper around raw BLS12-381 G2 public key bytes. Supports equality comparison and hex serialization. |
| `SigningPublicKey` | Wrapper around a derived BBS+ signing key. Includes `derive_signing_public_key(pub_key, total_messages)` static method. |

### `IssuerPublicData`

The authoritative metadata record for an Issuer, stored in the Registry and replicated in local caches.

| Field | Type | Description |
|-------|------|-------------|
| `issuer_name` | `str` | Unique issuer identifier |
| `public_key` | `PublicKeyBLS` | BLS public key |
| `revocation_bitstring` | `str` | Hex-encoded revocation status vector |
| `valid_until_weeks` | `int` | Default credential validity (epoch size) |
| `validity_window_days` | `int` | Re-issuance window |

Provides `check_revocation_status(bit_index_hex)` for revocation lookups.

### Attribute Model

#### `AttributeType` (Enum)

| Member | Value | Description |
|--------|-------|-------------|
| `REVEALED` | 1 | Visible to the Issuer during signing |
| `HIDDEN` | 2 | Blinded via Pedersen commitment |

#### `KeyedIndexedMessage`

Extends `bbs.IndexedMessage` with a `key` field (attribute name), allowing attributes to carry both a positional index and a human-readable label.

#### `IssuanceAttributes`

Manages the complete attribute set for a credential issuance. Handles:

- Sequential index assignment for BBS+ message positioning
- Separation of revealed vs. blinded attributes
- Pedersen commitment lifecycle (`build_commitment_append_meta()`)
- Automatic appending of metadata attributes (`metaHash`, `validUntil`, `revocationMaterial`)
- Blinding factor and commitment proof storage

### Request / Response Classes

All protocol messages inherit from `Request` and carry a `request_type: RequestType` discriminator.

| Class | Type | Direction | Description |
|-------|------|-----------|-------------|
| `VCIssuanceRequest` | `ISSUANCE` | Holder → Issuer | Initiates issuance |
| `FreshnessUpdateResponse` | `FRESHNESS` | Issuer → Holder | Session nonce |
| `BlindSignRequest` | `BLIND_SIGN` | Holder → Issuer | Commitment + proof + revealed attrs |
| `ForwardVCResponse` | `FORWARD_VC` | Issuer → Holder | Signed credential |
| `ForwardVpAndCmtRequest` | `FORWARD_VP_AND_CMT` | Holder → Issuer | VP of old VC + new commitment (re-issuance) |
| `VPRequest` | `VP_REQUEST` | Verifier → Holder | Attribute request + challenge nonce |
| `ForwardVPResponse` | `FORWARD_VP` | Holder → Verifier | ZKP proof + revealed attrs |
| `ErrorResponse` | `ERROR` | Issuer → Holder | Structured error with category |
| `RegisterIssuerDetailsRequest` | `REGISTER_ISSUER_DETAILS` | Issuer → Registry | Metadata announcement |
| `UpdateIssuerDetailsRequest` | `UPDATE_ISSUER_DETAILS` | Issuer → Registry | Metadata update |
| `GetIssuerDetailsRequest` | `GET_ISSUER_DETAILS` | Entity → Registry | Single issuer lookup |
| `IssuerDetailsResponse` | `ISSUER_DETAILS_RESPONSE` | Registry → Entity | Single issuer metadata |
| `BulkGetIssuerDetailsRequest` | `BULK_ISSUER_DETAILS_REQUEST` | Entity → Registry | Full registry sync |
| `BulkIssuerDetailsResponse` | `BULK_ISSUER_DETAILS_RESPONSE` | Registry → Entity | All registered issuers |

### Serialization & Polymorphic Dispatch

All request/response objects implement:

- **`to_dict()` / `from_dict()`** — Dictionary serialization with automatic hex encoding for binary fields.
- **`to_json()` / `from_json()`** — JSON string serialization.
- **`get_print_string()`** — Human-readable bordered output for debugging and protocol trail logging.
- **Polymorphic `Request.from_dict()`** — Factory method that inspects the `request_type` discriminator and reconstructs the correct subclass. This allows transport layers to receive generic JSON payloads and reconstruct typed objects without knowledge of the specific message type.

### Error Categories

| Error Type | Description | Trigger |
|------------|-------------|---------|
| `ISSUER_UNAVAILABLE` | Issuer is busy | Concurrent session attempts |
| `VERIFICATION_FAILED` | Crypto proof/signature failed | Tampered PoK or invalid commitments |
| `BITSTRING_EXHAUSTED` | No available revocation indices | Capacity exceeded |
| `INVALID_REQUEST` | Malformed payload | Attribute mismatches, missing fields |
| `INVALID_STATE` | Wrong protocol state | Out-of-order messages |

---

## `credential.py` — Credential & Presentation Models

### `VerifiableCredential`

A mock W3C Verifiable Credential for BBS+ signatures.

**Key features:**

- **`normalize_meta_fields()`** — Deterministic BLAKE2b hash of the credential envelope (context, type, issuer, subject keys in insertion order, proof label). Key order is preserved (not sorted) because BBS+ message indexing depends on it.
- **`prepare_verification_request(pub_key)`** — Builds a `bbs.VerifyRequest` by re-computing the `metaHash` and assembling the message list.
- **`prep_body_for_vp(credential, revealed_keys)`** — Creates a stripped-down copy of the credential containing only the disclosed attributes.

### `VerifiablePresentation`

W3C-style VP envelope that carries the ZKP proof and a selectively-disclosed credential.

**Key features:**

- **`normalize_meta_fields()`** — Hashes both the VP envelope and the embedded credential envelope (excluding variable proof values). Provides domain separation between VP-level and VC-level fields.
- **`build_bound_nonce(nonce, commitment=None)`** — Produces an effective nonce by hashing the Verifier's challenge with the VP metadata digest. Optionally includes a commitment for re-issuance binding.
- **`prepare_verification_request(pub_key, nonce, commitment=None)`** — Reconstructs the bound nonce and builds a `bbs.VerifyProofRequest` for proof verification. Derives the total message count directly from the proof bytes.

Both classes support full `to_dict()`/`from_dict()`/`to_json()`/`from_json()` serialization with proper hex encoding of binary proof fields.
