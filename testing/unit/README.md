# Unit Testing Suite

This directory contains the core functional and cryptographic integrity tests for the `BBS-ISS-Prototype-DMU` project. Tests are designed using `pytest` and are modularly separated into `entities`, `flows`, and `models` to evaluate state isolation, behavioral protocol flows, and mathematical edge cases respectively.

## Running the Tests

Ensure your virtual environment is activated and the `[dev]` dependencies are installed.

```bash
# Run the entire suite
pytest testing/unit/

# Run a specific test file with verbose output
pytest testing/unit/models/test_credential.py -v
```

---

## Test Categories

### `models/` - Cryptographic Payloads & Validation
Focuses intensely on the verifiable credential data structures and specific cryptographic requirements of BBS+ binding.

- **`test_credential.py`**: Ensures order-preserving hashing for BBS+ signatures, validates that structural mutations (context, type, issuer) successfully fracture the `metaHash`, checks JSON/Dict serialization roundtrips, and tests signature invalidation when metadata fields are tampered with.
- **`test_attributes.py`**: Validates internal attribute mappings. Checks that attempting to blindly sign zero hidden attributes actively rejects the request, and verifies that interleaving `REVEALED` and `HIDDEN` properties successfully maintain sequential indexing essential for BBS+.
- **`test_verifiable_presentation.py`**: Evaluates VP envelope structure. Tests correct extraction of VP subjects, dynamic binding of nonces across the envelope, and verifies that modifying the challenge or metadata effectively breaks the cryptographic binding.

### `entities/` - Participant State & Guardrails
Strictly enforces state-machine constraints and behavioral boundaries for each participant.

- **`test_issuer.py`**: Validates the `IssuerInstance`. Tests rejection of overlapping issuance sessions, ensuring an `IssuerNotAvailable` error is raised. Contains cryptographic checks against replay attacks, ensuring valid proofs with wrong nonces are properly rejected with a `ProofValidityError`.
- **`test_holder.py`**: Tests `HolderInstance` logic, specifically Verifiable Presentation extraction rules. Verifies out-of-order response rejection (`HolderNotInInteraction`), and enforces presentation guards like hidden key conflict rejections, missing attribute rejections, and metadata protections.
- **`test_verifier.py`**: Tests `VerifierInstance` state machine. Ensures that processing VPs without a pending challenge raises errors, verifies rejection of double concurrent presentations, and validates successful state resets after verification.

### `flows/` - End-to-End Protocols
Evaluates the core multi-round protocol mechanics.

- **`test_issuance.py`**: Executes complete multi-round issuances including pedersen commitments, zero-knowledge proofs, blind signing, and unblinding. Verifies that the FFI integration and protocol abstractions operate reliably. Tests concurrent issuances across multiple Holders and Issuers to prevent state pollution.
- **`test_presentation_flow.py`**: Tests full selective disclosure mechanics, including partial disclosures and verification completeness. Includes attack simulations like forging VPs with unrequested attributes or injecting rogue attributes to bypass validation.
- **`test_reissuance.py`**: Thoroughly verifies the "Forward VP with Commitment" re-issuance flow. Tests reissuance stress handling (100 parallel requests), strict replay protections (nonce or commitment substitutions), boundary enforcement for expiration, state resetting on failure, and checks the integrity of the new re-issued credentials (updated `validUntil`).
