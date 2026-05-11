# Exceptions — Custom Exception Hierarchy

This package defines all project-specific exceptions. Exceptions use the pattern `def __init__(self, message="<default>")` unless they accept additional diagnostic arguments.

## Exception Reference

### Attribute & Commitment Errors

| Exception | Default Message | Trigger |
|-----------|----------------|---------|
| `AttributesNotCommitted` | "Attributes not committed" | Accessing commitment data before `build_commitment_append_meta()` |
| `NoBlindedAttributes` | "No blinded attributes" | Calling `build_commitment_append_meta()` without hidden attributes |
| `NoRevealedAttributes` | "No revealed attributes" | Calling `get_revealed_attributes()` when none exist |

### Entity State Errors

| Exception | Default Message | Trigger |
|-----------|----------------|---------|
| `IssuerNotAvailable` | "Issuer is processing another request" | Concurrent issuance/re-issuance attempt |
| `HolderNotInInteraction` | "Holder is not in an active interaction" | `process_request()` without prior `issuance_request()` |
| `VerifierNotInInteraction` | "Verifier is not in an active interaction" | `process_request()` without prior `presentation_request()` |
| `HolderStateError` | "Invalid holder state" | State precondition not met. Accepts optional `state` kwarg for diagnostic dump. |
| `VerifierStateError` | "Invalid verifier state" | State precondition not met. Accepts optional `state` kwarg. |
| `IssuerStateError` | "Invalid issuer state" | State precondition not met. Accepts optional `state` kwarg. |

### Cryptographic Errors

| Exception | Default Message | Trigger |
|-----------|----------------|---------|
| `ProofValidityError` | "Invalid proof" | BBS+ signature verification failure (Holder unblinding) or commitment proof failure (Issuer blind sign) |
| `FreshnessValueError` | "Invalid freshness value" | Nonce mismatch during commitment verification |

### Registry & Cache Errors

| Exception | Default Message | Trigger |
|-----------|----------------|---------|
| `UnregisteredIssuerError` | "Issuer not found in registry" | Registry resolution returns no data for a pending issuance |
| `IssuerNotFoundInCacheError` | "Issuer not found in local cache" | Direct cache access without registry fallback |

### Capacity & Validation Errors

| Exception | Default Message | Trigger |
|-----------|----------------|---------|
| `BitstringExhaustedError` | "No available indices in bitstring..." | Revocation bitstring full with no reclaimable expired bits |
| `MissingAttributeError` | "Required attribute missing" | Verifier policy check finds missing `validUntil` or `revocationMaterial` |
| `VerifierTimeoutError` | "VP request timed out" | Orchestrator-level VP interaction timeout expired |

## State Diagnostic Dumps

`HolderStateError`, `VerifierStateError`, and `IssuerStateError` accept an optional `state` keyword argument. When provided, the error message appends a formatted dump of all state attributes, which is useful for debugging protocol state machine violations.
