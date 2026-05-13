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

The Issuer generates BLS12-381 G2 keypairs and manages the lifecycle of verifiable credentials.

### Technical Implementation: Bitstring Manager & Reclamation
Revocation is managed via a `BitstringManager` that enforces epoch-based bit reclamation:
- **Bit Allocation**: Each new credential is assigned a sequential index.
- **Reclamation Logic**: When the bitstring reaches its maximum capacity (defined in `demo_configuration.py`), the manager scans for indices belonging to expired credentials (based on their `validUntil` field relative to the current epoch). 
- **Capacity Exhaustion**: If no bits can be reclaimed, the issuer raises a `BitstringExhaustedError`, which the orchestrator converts into a structured `BITSTRING_EXHAUSTED` error response.

### Technical Implementation: Epoch Alignment
To prevent correlation attacks, the Issuer enforces rigid epoch boundaries:
- **Calculation**: `validUntil = baseline + (current_epoch + 1) * epoch_size`.
- **Window Bumping**: If a request arrives within the `re_issuance_window` (e.g., 7 days before the boundary), the issuer automatically increments the epoch count, effectively issuing a credential that is valid for the remainder of the current epoch *plus* the entire next epoch.

---

## `holder.py` — HolderInstance

### Technical Implementation: Pedersen Commitments
The Holder builds commitments over attributes marked as `HIDDEN` in the schema (primarily the `LinkSecret`):
- **Blinding Factor**: A random 32-byte scalar is generated per issuance.
- **Commitment Proof**: The Holder generates a Zero-Knowledge Proof of Knowledge (PoK) of the committed values, bound to the Issuer's freshness nonce to prevent replay attacks.

### Technical Implementation: Unblinding
Upon receiving a `ForwardVCResponse`, the Holder must unblind the signature:
1. Reconstructs the full message vector by merging revealed attributes with the local hidden values.
2. Calls the underlying `bbs_signatures` FFI to unblind the `BlindSignature` object into a standard `Signature` using the original blinding factor.

---

## `verifier.py` — VerifierInstance

### Technical Implementation: ZKP Verification
The Verifier performs cryptographic verification of the `VerifiablePresentation`:
1. **Nonce Binding**: To prevent "Proof-Mining" attacks where a Holder reuses a proof across different verifiers, the Verifier computes a **Bound Nonce**: `blake2b(VerifierNonce + VP_Metadata_Hash)`.
2. **Proof Verification**: Calls `ursa_bbs_signatures.verify_proof`. This verifies that the signature is valid, the attributes match the disclosed set, and the proof was generated specifically for this bound nonce.

### Technical Implementation: Validity Checks
- **Expiration**: Compares `validUntil` (disclosed in the VP) against the Verifier's local UTC clock.
- **Revocation**: If `revocationMaterial` is disclosed, the Verifier extracts the bit index and checks it against the Issuer's latest bitstring (retrieved from the `PublicDataCache`).

---

## `registry.py` — RegistryInstance

### Technical Implementation: Passive State
The Registry is a thread-safe Key-Value store. It uses a standard Python dictionary protected by the Flask request context (in networked mode) or direct object access. It enforces that `issuer_name` is unique and that `Update` requests can only modify existing records.
nd does not initiate any protocol flows.
