# BBS+ Issuance Prototype — Unit Test Suite

This directory contains the comprehensive unit test suite for the BBS+ verifiable credential system. The suite is semantically partitioned to ensure granular coverage of cryptographic models, participant state machines, and end-to-end protocol flows.

## 1. Models (`models/`)
Tests in this category validate the core data structures, cryptographic hashing, and serialization logic.

### `test_attributes.py` — Issuance Attributes Logic
*   **`test_commitment_requires_hidden_attributes`**: Ensures that `NoBlindedAttributes` is raised if a commitment is attempted without any attributes marked as `HIDDEN`.
*   **`test_attribute_sequencing_and_indexing`**: Verifies that indices are assigned sequentially (0, 1, 2...) regardless of the attribute type, ensuring consistency for BBS+ signing.

### `test_credential.py` — Verifiable Credential Integrity
*   **`test_order_preserving_hashing`**: Confirms that changing the insertion order of attributes results in a different `metaHash`, protecting against reordering attacks.
*   **`test_hash_changes_on_modification`**: Verifies that modifying top-level fields (`@context`, `type`, `issuer`) or renaming `credentialSubject` keys produces a new `metaHash`.
*   **`test_serialization_roundtrip`**: Ensures that `to_dict`/`to_json` and their inverse methods preserve all data, including binary proofs (hex-encoded) and key ordering.
*   **BBS+ Integrity Guards**:
    *   `test_signature_invalid_on_context_change`
    *   `test_signature_invalid_on_type_change`
    *   `test_signature_invalid_on_issuer_change`
    *   `test_signature_invalid_on_subject_change`
    *   *These tests confirm that modifying any part of the credential envelope (revealed or hidden) invalidates the BBS+ signature.*

### `test_verifiable_presentation.py` — ZKP Envelope & Nonce Binding
*   **`TestVPSerialisation`**: Validates hex-encoding of ZKP proofs and full dictionary/JSON roundtrips.
*   **`TestNormalizeMetaFields`**: 
    *   Ensures deterministic hashing of the VP metadata.
    *   Verifies domain separation (the `vc.` prefix) to prevent cross-level collisions between VP and VC fields.
    *   Confirms that the hash is insensitive to variable values (ZKP proof bytes, revealed attribute values) but sensitive to all structural metadata.
*   **`TestBuildBoundNonce`**: Validates the construction of the *effective nonce* (binding the verifier's challenge to the metadata). Verifies that different challenges or different metadata result in unique bound nonces.

---

## 2. Entities (`entities/`)
Tests focused on the internal state machines and behavioral guardrails of the protocol participants.

### `test_holder.py` — Holder State & VP Construction
*   **`TestBuildVP`**: Validates that `build_vp` correctly strips hidden attributes from the `credentialSubject` and produces a valid VP envelope.
*   **`TestEntityVPHolderGuards`**:
    *   `test_hidden_key_conflict_raises`: Rejects revealing keys explicitly marked as "always hidden".
    *   `test_metahash_conflict_raises`: Prevents the leak of the internal `metaHash` field.
    *   `test_nonexistent_credential_raises`: Ensures error handling for invalid credential names.
    *   `test_unavailable_attribute_raises`: Rejects requests for attributes not present in the VC.
*   **`test_holder_rejects_out_of_order_responses`**: Enforces the issuance state machine (e.g., rejecting a VC response if no freshness challenge was processed).

### `test_issuer.py` — Issuer Availability & Proof Validation
*   **`test_issuer_rejects_overlapping_sessions`**: Confirms that the Issuer raises `IssuerNotAvailable` if a new session starts while another is active.
*   **`test_issuer_rejects_replayed_proof`**: Verifies that a valid commitment proof from one session is rejected if replayed in another session (nonce binding).

### `test_verifier.py` — Verifier Session Management
*   **`test_process_request_without_challenge_raises`**: Rejects incoming VPs if no challenge nonce was issued.
*   **`test_double_presentation_request_raises`**: Prevents the Verifier from starting multiple concurrent sessions.
*   **`test_verifier_resets_after_verification`**: Ensures the Verifier returns to an idle state after a successful interaction.

---

## 3. Flows (`flows/`)
End-to-end integration tests that exercise the multi-step protocol sequences and security boundaries.

### `test_issuance.py` — Blind Issuance Protocol
*   **`test_successful_issuance`**: A stress test running 500 complete 4-step issuance cycles to ensure reliability and cryptographic stability.
*   **`test_concurrent_issuance_separation`**: Confirms that multiple issuers and holders can operate simultaneously without state leakage or nonce collisions.

### `test_presentation_flow.py` — Selective Disclosure & ZKP Verification
*   **Cryptographic Boundary Tests**:
    *   `test_valid_vp_verifies`: Basic end-to-end success.
    *   `test_selective_disclosure`: Tests various subsets of revealed attributes (single field, all fields).
    *   `test_tampering`: Comprehensive tests verifying that modifying issuer DIDs, contexts, or attribute values breaks the ZKP.
    *   `test_nonce_binding`: Rejects VPs built against rogue or stale nonces.
    *   `test_replay_attack_fails`: Ensures a VP from a past session cannot be reused against a new verifier challenge.
*   **Entity API Tests**: Exercises the high-level `VerifierInstance` and `HolderInstance` interaction methods.

### `test_reissuance.py` — Forward VP with Commitment Protocol
*   **`test_stress_reissuance`**: Runs 100 sequential reissuance rounds on a single credential.
*   **`test_replay_different_commitment`**: **Critical Security Test.** Prevents an attacker from substituting a new commitment into a captured VP (Substitution Attack protection).
*   **`test_attribute_modification`**: Ensures the Issuer verifies that the re-issued attributes match the original ones revealed in the VP.
*   **`test_reissuance_window_boundary`**: Validates the `validUntil` expiration logic and the re-issuance window enforcement.
*   **`test_reissued_credential_integrity`**: Confirms that the new credential has a refreshed expiry while maintaining the same `metaHash` for long-term attribute binding.
