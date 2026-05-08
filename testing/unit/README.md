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

*   **`TestBuildBoundNonce`**: Validates the construction of the *effective nonce* (binding the verifier's challenge to the metadata). Verifies that different challenges or different metadata result in unique bound nonces.

### `test_requests_api.py` — Data Model Serialization
*   **`test_issuer_public_data_serialization`**: Verifies that `IssuerPublicData` maintains full integrity across JSON and dictionary round-trips.
*   **`test_issuer_public_data_revocation_check`**: Validates the `check_revocation_status` helper against hex-encoded bitstrings and various bit indices.
*   **`test_cache_entry_serialization`**: Ensures that `CacheEntry` objects (including timestamps) are correctly serialized.
*   **`test_public_key_bls_equality`**: Confirms that BLS public key objects can be compared reliably.

### `test_cache.py` — Public Data Cache Management
*   **`test_cache_update_and_get`**: Validates cache hit/miss logic and automatic UTC timestamping.
*   **`test_cache_check_bit_index`**: Verifies the high-level revocation check, ensuring it delegates correctly and raises `IssuerNotFoundInCacheError` for missing issuers.
*   **`test_cache_clear`**: Ensures the cache can be completely purged.
*   **`test_cache_info_formatting`**: Verifies that `get_cache_info()` produces a correctly formatted summary string for both empty and populated states.

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
*   **Epoch Boundary Logic**:
    *   `test_epoch_boundary_initial_issuance_outside_window`: Initial issuance correctly snaps to the next calculated epoch boundary.
    *   `test_epoch_boundary_initial_issuance_inside_window`: Bumps to the next boundary if issuance occurs inside the re-issuance window.
    *   `test_epoch_boundary_before_baseline`: Ensures logic functions correctly for dates prior to the configured baseline.
    *   `test_epoch_boundary_late_issuance`: Confirms that outdated credentials re-sync to the currently active epoch.
    *   `test_epoch_boundary_late_issuance_inside_window`: Proves that re-issuing an outdated credential near an epoch boundary bumps to the *next* epoch, preventing immediate expiration.

*   **`test_verifier_resets_after_verification`**: Ensures the Verifier returns to an idle state after a successful interaction.

### `test_registry.py` — Registry Dispatch & Data Persistence
*   **`test_registry_registration_and_get`**: Verifies the core registration and retrieval transactional logic.
*   **`test_registry_registration_conflict`**: Enforces issuer name uniqueness (idempotency).
*   **`test_registry_update`**: Validates that existing issuer metadata can be securely updated.
*   **`test_registry_bulk_get`**: Confirms that the bulk request returns the complete set of registered issuers.

---

## 3. Flows (`flows/`)
End-to-end integration tests that exercise the multi-step protocol sequences and security boundaries.

*   **`test_successful_issuance`**: A stress test running 500 complete 4-step issuance cycles to ensure reliability and cryptographic stability.
*   **`test_concurrent_issuance_separation`**: Confirms that multiple issuers and holders can operate simultaneously without state leakage or nonce collisions.

### `test_holder_resolution.py` — Proactive Issuer Resolution
*   **`test_holder_resolution_on_issuance`**: Validates that the Holder proactively resolves unknown issuers during `issuance_request` and resumes correctly.
*   **`test_holder_resolution_failure`**: Confirms that the Holder raises `UnregisteredIssuerError` if the registry cannot resolve the issuer.
*   **`test_holder_resolution_cache_hit`**: Verifies immediate issuance when the issuer is already cached.

### `test_presentation_flow.py` — Selective Disclosure & ZKP Verification
*   **Cryptographic Boundary Tests**:
    *   `test_valid_vp_verifies`: Basic end-to-end success.
    *   `test_selective_disclosure`: Tests various subsets of revealed attributes (single field, all fields).
    *   `test_tampering`: Comprehensive tests verifying that modifying issuer DIDs, contexts, or attribute values breaks the ZKP.
    *   `test_nonce_binding`: Rejects VPs built against rogue or stale nonces.
    *   `test_replay_attack_fails`: Ensures a VP from a past session cannot be reused against a new verifier challenge.
*   **Entity API Tests**: Exercises the high-level `VerifierInstance` and `HolderInstance` interaction methods.

### `test_verifier_resolution.py` — Asynchronous Verifier Resolution
*   **`test_verifier_resolution_on_cache_miss`**: Validates that the Verifier parks unknown VPs, resolves the issuer, and automatically resumes verification.
*   **`test_verifier_resolution_on_key_mismatch`**: Ensures the Verifier re-resolves the issuer if the cached public key does not match the one in the VP.
*   **`test_verifier_resolution_failure`**: Confirms that verification fails (with no errors) if the registry lookup returns no data.

*   **`test_reissued_credential_integrity`**: Confirms that instantaneous re-issuance maintains the exact same epoch boundary and `metaHash`.

### `test_registry_protocol.py` — Cross-Entity Synchronization
*   **`test_issuer_registration_flow`**: Validates the full Issuer ↔ Registry handshake for new registrations.
*   **`test_holder_lazy_lookup_flow`**: Proves the "Cache-First, Registry-Second" behavior of the Holder lookup system.
*   **`test_verifier_bulk_sync_flow`**: Verifies that Verifiers can perform a full-registry synchronization in a single interaction.
*   **State Guardrail Tests**: Rejects unsolicited or out-of-order registry responses to prevent session hijacking or state corruption.
