# Entities — Protocol Participants

This package contains the four core protocol entities. Each entity is a self-contained state machine that processes protocol messages via a `process_request()` dispatch method. Entities operate at the cryptographic layer — they have no knowledge of transport mechanisms or orchestration logic.

## Architecture

All entities inherit from `Entity` (defined in `entity.py`), which enforces the `process_request()` interface. Each entity maintains its own internal `State` object that tracks whether it is idle or mid-interaction.

```
Entity (ABC)
├── IssuerInstance
├── HolderInstance
├── VerifierInstance
└── RegistryInstance
```

---

## `entity.py` — Abstract Base

Defines the `Entity` abstract base class with a single abstract method:

| Method | Description |
|--------|-------------|
| `process_request(request)` | Dispatch incoming protocol messages to internal handlers. |

---

## `issuer.py` — IssuerInstance

The Issuer generates BLS12-381 G2 keypairs, enforces nonce-based session freshness, verifies Pedersen commitment proofs, and computes blind BBS+ signatures.

### Key Responsibilities

- **Key Generation**: Generates a BLS keypair from a 32-byte random seed at instantiation.
- **Freshness Enforcement**: Issues a random 32-byte nonce per session, binding commitments to prevent replay.
- **Schema Management**: Manages a `CredentialSchema` (via `get_schema()` and `set_schema()`) which defines the credential types, contexts, and exact structural ordering of attribute keys during issuance.
- **Blind Signing**: Verifies the Holder's blinded commitment proof, then computes a blind BBS+ signature over the combined revealed + committed attributes according to the schema.
- **VC Construction**: Builds the `VerifiableCredential` skeleton, computes the deterministic `metaHash`, assigns epoch-aligned `validUntil` timestamps, and allocates revocation bitstring indices.
- **Re-issuance**: Verifies the Holder's VP of an existing credential, checks temporal validity and revocation status, revokes the old index, and issues a renewed VC.
- **Error Responses**: Catches internal failures (proof invalidity, capacity exhaustion, state violations) and returns structured `ErrorResponse` messages instead of propagating raw exceptions.

### Epoch-Based Expiration

All credentials are aligned to a global epoch grid (configurable via `set_epoch_size_days()`). Credentials issued within the `re_issuance_window_days` of an upcoming boundary are automatically bumped to the next epoch, preventing near-expiry issuance.

### Bitstring Management

Revocation state is tracked via `BitstringManager` with epoch-based bit reclamation. When capacity is exhausted and no expired bits are reclaimable, `BitstringExhaustedError` is raised.

### State Machine

| State | Description |
|-------|-------------|
| `available=True` | Ready for new requests |
| `available=False, type=ISSUANCE` | Processing an issuance session |
| `available=False, type=RE_ISSUANCE` | Processing a re-issuance session |

Concurrent requests while busy return an `ErrorResponse` with `ISSUER_UNAVAILABLE`.

---

## `holder.py` — HolderInstance

The Holder initiates credential issuance, builds Pedersen commitments over private attributes, unblinds received signatures, and constructs zero-knowledge proofs for selective disclosure.

### Key Responsibilities

- **Issuance Initiation**: Resolves the target Issuer's public key (cache-first, with automatic registry fallback) and starts the issuance handshake.
- **Commitment Construction**: Builds a Pedersen commitment over blinded attributes using the Issuer's nonce. Automatically appends `metaHash`, `validUntil`, and `revocationMaterial` placeholders as revealed metadata attributes.
- **Unblinding & Verification**: After receiving the blind-signed VC, unblinds the signature using the stored blinding factor, fills in hidden attribute values, recomputes `metaHash`, and verifies the full BBS+ signature.
- **Credential Storage**: Stores verified credentials in an internal `credentials` dictionary keyed by user-defined names.
- **VP Construction**: Given a `VPRequest`, resolves the credential, builds a `VerifiablePresentation` with only the requested attributes, derives a bound nonce (binding VP metadata to the Verifier's challenge), and creates a BBS+ ZKP proof.
- **Re-issuance**: Presents the old credential as a VP while simultaneously building a new commitment for the renewed credential, all bound to the same session nonce.

### Asynchronous Registry Resolution

If the Holder encounters an unknown Issuer during `issuance_request()`, it suspends the current flow, stores the pending parameters in `State.pending_issuer_name`, and returns a `GetIssuerDetailsRequest`. When the registry response arrives, `process_request()` automatically resumes the suspended issuance.

### State Machine

| State | Description |
|-------|-------------|
| `available=True` | Ready for new interactions |
| `blind_sign_request_ready` | Awaiting freshness nonce for commitment |
| `unblind_ready` | Nonce received, ready to build commitment |
| `pending_issuer_name != None` | Suspended, awaiting registry resolution |

---

## `verifier.py` — VerifierInstance

The Verifier issues challenge nonces, verifies BBS+ zero-knowledge proofs, checks attribute completeness, and performs policy-level validity checks (expiration, revocation).

### Key Responsibilities

- **Presentation Request**: Generates a random 32-byte challenge nonce and records the requested attributes in its state.
- **ZKP Verification**: Reconstructs the bound nonce (identical to the Holder's construction), then verifies the BBS+ proof against the Issuer's public key.
- **Attribute Completeness**: Before cryptographic verification, checks that all originally requested attributes are present in the VP.
- **Validity Checks**: `check_validity()` performs expiration checks against `validUntil` and optional revocation checks against the cached Issuer bitstring.

### Asynchronous Registry Resolution

If the Verifier receives a VP from an unknown Issuer, it parks the VP in `State.queued_response` and returns a `GetIssuerDetailsRequest`. When the registry response arrives, it automatically resumes verification.

### State Machine

| State | Description |
|-------|-------------|
| `available=True` | Ready for new requests |
| `available=False, type=VP_REQUEST` | Awaiting VP response from Holder |
| `queued_response != None` | VP parked, awaiting registry resolution |

---

## `registry.py` — RegistryInstance

A centralized authority that stores and serves `IssuerPublicData` records.

### Key Responsibilities

- **Registration**: Accepts `RegisterIssuerDetailsRequest` from Issuers, validates and stores their metadata.
- **Updates**: Accepts `UpdateIssuerDetailsRequest` to refresh existing metadata (e.g., rotated revocation bitstrings).
- **Lookup**: Serves `GetIssuerDetailsRequest` with the corresponding `IssuerDetailsResponse`.
- **Bulk Sync**: Serves `BulkGetIssuerDetailsRequest` with the full set of registered Issuers.

The Registry is a passive entity — it only responds to incoming requests and does not initiate any protocol flows.
