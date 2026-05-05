import pytest
import copy
import os
from bbs_iss.interfaces.credential import VerifiableCredential, VerifiablePresentation


# ── Helpers ──────────────────────────────────────────────────────────

def _make_vc_body(
    proof=None,
    issuer="did:example:issuer-123",
    subject=None,
):
    """Returns a dict resembling the embedded verifiableCredential inside a VP."""
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://example.org/contexts/student-card-v1"
        ],
        "type": ["VerifiableCredential", "StudentCard"],
        "issuer": issuer,
        "credentialSubject": subject or {"name": "Alice", "studentId": "S-001"},
        "proof": proof,
    }


def _make_vp(vc_body=None, proof=None):
    """Builds a VP with sensible defaults."""
    body = vc_body or _make_vc_body(proof=proof or b"\xde\xad" * 16)
    return VerifiablePresentation(verifiableCredential=body)


# ── Serialisation ────────────────────────────────────────────────────

class TestVPSerialisation:

    def test_to_dict_contains_expected_keys(self):
        vp = _make_vp()
        d = vp.to_dict()
        assert "@context" in d
        assert "type" in d
        assert "verifiableCredential" in d

    def test_proof_bytes_converted_to_hex_in_to_dict(self):
        proof_bytes = os.urandom(32)
        vp = _make_vp(proof=proof_bytes)
        d = vp.to_dict()
        assert d["verifiableCredential"]["proof"] == proof_bytes.hex()

    def test_from_dict_restores_proof_as_bytes(self):
        proof_bytes = os.urandom(32)
        vp = _make_vp(proof=proof_bytes)
        d = vp.to_dict()
        restored = VerifiablePresentation.from_dict(d)
        assert restored.verifiableCredential["proof"] == proof_bytes

    def test_dict_roundtrip_preserves_all_fields(self):
        vp = _make_vp()
        d = vp.to_dict()
        restored = VerifiablePresentation.from_dict(d)
        assert restored.context == vp.context
        assert restored.type == vp.type
        assert restored.verifiableCredential["issuer"] == vp.verifiableCredential["issuer"]
        assert (
            restored.verifiableCredential["credentialSubject"]
            == vp.verifiableCredential["credentialSubject"]
        )

    def test_json_roundtrip_preserves_all_fields(self):
        vp = _make_vp()
        json_str = vp.to_json()
        restored = VerifiablePresentation.from_json(json_str)
        assert restored.context == vp.context
        assert restored.type == vp.type
        assert restored.verifiableCredential["proof"] == vp.verifiableCredential["proof"]

    def test_none_verifiable_credential_serialises_cleanly(self):
        vp = VerifiablePresentation()
        d = vp.to_dict()
        assert d["verifiableCredential"] is None
        restored = VerifiablePresentation.from_dict(d)
        assert restored.verifiableCredential is None


# ── add_proof ────────────────────────────────────────────────────────

class TestAddProof:

    def test_add_proof_sets_value(self):
        vp = _make_vp(proof=None)
        new_proof = os.urandom(48)
        vp.add_proof(new_proof)
        assert vp.verifiableCredential["proof"] == new_proof

    def test_add_proof_overwrites_existing(self):
        vp = _make_vp(proof=b"\x00" * 16)
        new_proof = os.urandom(48)
        vp.add_proof(new_proof)
        assert vp.verifiableCredential["proof"] == new_proof


# ── normalize_meta_fields ────────────────────────────────────────────

class TestNormalizeMetaFields:

    def test_deterministic(self):
        """Calling normalize_meta_fields twice on the same VP returns the same digest."""
        vp = _make_vp()
        assert vp.normalize_meta_fields() == vp.normalize_meta_fields()

    def test_hex_digest_length(self):
        """blake2b with 32-byte digest → 64 hex chars."""
        vp = _make_vp()
        assert len(vp.normalize_meta_fields()) == 64

    def test_changes_on_vp_context_modification(self):
        vp = _make_vp()
        base = vp.normalize_meta_fields()
        vp.context = vp.context + ["https://example.com/extra"]
        assert vp.normalize_meta_fields() != base

    def test_changes_on_vp_type_modification(self):
        vp = _make_vp()
        base = vp.normalize_meta_fields()
        vp.type = vp.type + ["ExtraType"]
        assert vp.normalize_meta_fields() != base

    def test_changes_on_vc_context_modification(self):
        vp = _make_vp()
        base = vp.normalize_meta_fields()
        vp.verifiableCredential["@context"].append("https://evil.com")
        assert vp.normalize_meta_fields() != base

    def test_changes_on_vc_type_modification(self):
        vp = _make_vp()
        base = vp.normalize_meta_fields()
        vp.verifiableCredential["type"].append("FakeType")
        assert vp.normalize_meta_fields() != base

    def test_changes_on_vc_issuer_modification(self):
        vp = _make_vp()
        base = vp.normalize_meta_fields()
        vp.verifiableCredential["issuer"] = "did:evil:attacker"
        assert vp.normalize_meta_fields() != base

    def test_changes_on_credential_subject_key_modification(self):
        vp = _make_vp()
        base = vp.normalize_meta_fields()
        # Replace a key while keeping the same set of values
        subj = vp.verifiableCredential["credentialSubject"]
        subj["injectedKey"] = subj.pop("name")
        assert vp.normalize_meta_fields() != base

    def test_vp_vs_vc_context_domain_separation(self):
        """Moving a context string from VP-level to VC-level must produce a different hash,
        confirming the 'vc.' tag prefix prevents cross-level collisions."""
        extra_ctx = "https://example.com/extra"

        vp_a = _make_vp()
        vp_a.context = vp_a.context + [extra_ctx]

        vp_b = _make_vp()
        vp_b.verifiableCredential["@context"].append(extra_ctx)

        assert vp_a.normalize_meta_fields() != vp_b.normalize_meta_fields()

    def test_insensitive_to_proof_value(self):
        """The proof value itself is not hashed (only a marker), so changing it should not affect the digest."""
        vp_a = _make_vp(proof=b"\x00" * 32)
        vp_b = _make_vp(proof=b"\xff" * 32)
        assert vp_a.normalize_meta_fields() == vp_b.normalize_meta_fields()

    def test_insensitive_to_credential_subject_values(self):
        """Only keys are hashed; different values with the same keys must produce the same digest."""
        vp_a = _make_vp(vc_body=_make_vc_body(
            proof=b"\x00", subject={"name": "Alice", "age": "30"}
        ))
        vp_b = _make_vp(vc_body=_make_vc_body(
            proof=b"\x00", subject={"name": "Bob", "age": "99"}
        ))
        assert vp_a.normalize_meta_fields() == vp_b.normalize_meta_fields()


# ── build_bound_nonce ────────────────────────────────────────────────

class TestBuildBoundNonce:

    def test_deterministic(self):
        vp = _make_vp()
        nonce = os.urandom(32)
        assert vp.build_bound_nonce(nonce) == vp.build_bound_nonce(nonce)

    def test_output_is_32_bytes(self):
        """Result should always be 32 bytes (blake2b digest)."""
        nonce = os.urandom(32)
        vp = _make_vp()
        bound = vp.build_bound_nonce(nonce)
        assert len(bound) == 32

    def test_differs_from_raw_nonce(self):
        nonce = os.urandom(32)
        vp = _make_vp()
        bound = vp.build_bound_nonce(nonce)
        assert bound != nonce

    def test_different_nonce_produces_different_result(self):
        vp = _make_vp()
        n1 = os.urandom(32)
        n2 = os.urandom(32)
        assert vp.build_bound_nonce(n1) != vp.build_bound_nonce(n2)

    def test_different_metadata_produces_different_result(self):
        nonce = os.urandom(32)
        vp_a = _make_vp()
        vp_b = _make_vp()
        vp_b.verifiableCredential["issuer"] = "did:evil:changed"
        assert vp_a.build_bound_nonce(nonce) != vp_b.build_bound_nonce(nonce)
