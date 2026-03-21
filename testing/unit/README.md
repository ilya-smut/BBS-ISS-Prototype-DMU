# Unit Testing Suite

This directory contains the core functional and cryptographic integrity tests for the `BBS-ISS-Prototype-DMU` project. Tests are designed using `pytest` and prioritize evaluating state isolation, behavioral protocol flows, and mathematical edge cases over rigid implementations.

## Running the Tests

Ensure your virtual environment is activated and the `[dev]` dependencies are installed.

```bash
# Run the entire suite
pytest testing/unit/

# Run a specific test file with verbose output
pytest testing/unit/test_credential.py -v
```

---

## Test Modules

### `test_credential.py`
Focuses intensely on the verifiable credential data structure and the specific cryptographic requirements of BBS+ binding.

- **`test_order_preserving_hashing`**: Because BBS+ signatures are order-sensitive (attributes are mapped computationally to vector indices), the `normalize_meta_fields` logic must strictly preserve insertion order when hashing credential subject metadata. This test ensures that dynamically reordering identical attributes yields a fundamentally different signature target hash.
- **`test_hash_changes_on_modification`**: Tests that mutating any core field (`@context`, `type`, `issuer`, or `credentialSubject` keys) successfully fractures the `metaHash`.
- **`test_serialization_roundtrip`**: Verifies that standard serialization mechanics (`to_dict`, `from_dict`, `to_json`, `from_json`) preserve both the payload and the cryptographic signature payload without data-loss.
- **Signature Invalidation Tests (`test_signature_invalid_on_context_change`, etc.)**: Simulates a legitimate issuance, then mutates various segments of the credential, verifying that the BBS+ signature fails on attempting to verify the broken mathematical bindings.

### `test_issuance_flow.py`
Evaluates the core 4-round protocol mechanics.

- **`test_successful_issuance`**: Executes 500 complete multi-round issuances (request → freshness → blind_sign → forward_vc) including pedersen commitments, zero-knowledge proofs, blind signing, and unblinding. Demonstrates that the FFI integration and protocol abstractions operate flawlessly and reliably.
- **`test_concurrent_issuance_separation`**: Initiates multiple parallel issuances across multiple Holder and Issuer instances. Evaluates structural separation, ensuring freshness nonces and cryptographic state objects do not cross-pollinate or leak.

### `test_participant_states.py`
Strictly enforces state-machine constraints and cryptographic proof validation boundaries.

- **`test_issuer_rejects_overlapping_sessions`**: Validates the `IssuerInstance.State` constraints. Asserts `IssuerNotAvailable` is raised if a new `ISSUANCE` request hits while an interaction is already in progress.
- **`test_holder_rejects_out_of_order_responses`**: Evaluates `HolderInstance` state transitions. Proves the Holder strictly drops protocol violations, like receiving a `ForwardVCResponse` before a `FreshnessUpdateResponse`, raising `HolderStateError`.
- **`test_issuer_rejects_replayed_proof`**: A highly specific cryptographic evaluation against replay attacks. Generates a perfectly valid BBS+ blinded commitment proof in Session 2 and feeds it to Session 1. The proof will parse perfectly through the Rust FFI framework seamlessly (valid lengths & G1/G2 compressions) but perfectly asserts `ProofValidityError` mathematically because it misaligns with Session 1's freshly generated security nonce.

### `test_attributes.py`
Validates the internal mapping and extraction architectures translating pythonic abstractions down to `ursa-bbs-signatures` formats.

- **`test_commitment_requires_hidden_attributes`**: Validates that blindly signing zero hidden configurations actively rejects the request with a `NoBlindedAttributes` execution stop. 
- **`test_attribute_sequencing_and_indexing`**: Checks that mixing and interlacing `REVEALED` and `HIDDEN` properties successfully handles abstract separation simultaneously with absolute sequential vector assignments necessary for BBS+ verifications.
