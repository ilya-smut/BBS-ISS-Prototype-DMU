import pytest
import os
import copy
import ursa_bbs_signatures as bbs
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.interfaces.credential import VerifiableCredential, VerifiablePresentation
from bbs_iss.exceptions.exceptions import VerifierNotInInteraction, VerifierStateError
import bbs_iss.interfaces.requests_api as api
from bbs_iss.utils.utils import gen_link_secret


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def issued_credential():
    """
    Fixture that runs the full 4-step issuance flow and returns
    (holder, issuer, credential_name).
    """
    issuer = IssuerInstance()
    holder = HolderInstance()

    attributes = api.IssuanceAttributes()
    attributes.append("name", "Alice", api.AttributeType.REVEALED)
    attributes.append("age", "30", api.AttributeType.REVEALED)
    attributes.append("studentId", "STU-2026-001", api.AttributeType.REVEALED)
    attributes.append("linkSecret", gen_link_secret(), api.AttributeType.HIDDEN)

    cred_name = "student-card"

    # Step 1 → 2 → 3 → 4
    issuer_name = "Mock-Issuer"
    data = api.IssuerPublicData(issuer_name, issuer.public_key, "0"*10, 52, 7)
    holder.public_data_cache.update(issuer_name, data)
    
    init_req = holder.issuance_request(
        issuer_name=issuer_name,
        attributes=attributes,
        cred_name=cred_name,
    )
    freshness = issuer.process_request(init_req)
    blind_req = holder.process_request(freshness)
    forward_vc = issuer.process_request(blind_req)
    assert holder.process_request(forward_vc) is True

    return holder, issuer, cred_name


def _sync_verifier(verifier, issuers: list):
    """Helper: registers issuers and syncs verifier cache."""
    registry = RegistryInstance()
    for issuer in issuers:
        reg_req = issuer.register_issuer()
        reg_resp = registry.process_request(reg_req)
        issuer.process_request(reg_resp)
    
    bulk_req = verifier.fetch_all_issuer_details()
    bulk_resp = registry.process_request(bulk_req)
    verifier.process_request(bulk_resp)


def _process_vp(verifier, registry, response):
    """
    Helper: processes a VP response, handling potential registry resolution.
    
    This is necessary because some tests (e.g., tampering or key mismatches) 
    deliberately trigger the Verifier's resolution logic. In these cases, 
    process_request() returns a GetIssuerDetailsRequest instead of a result tuple.
    This helper completes the interaction loop with the registry so the 
    test can receive the final (False, ...) result.
    """
    res = verifier.process_request(response)
    if isinstance(res, api.GetIssuerDetailsRequest):
        reg_resp = registry.process_request(res)
        res = verifier.process_request(reg_resp)
    return res


def _full_entity_flow(holder, issuer, cred_name, requested_attrs):
    """Helper: runs the VP entity flow and returns the verifier result tuple."""
    verifier = VerifierInstance()
    _sync_verifier(verifier, [issuer])
    vp_request = verifier.presentation_request(requested_attributes=requested_attrs)
    vp_response = holder.present_credential(
        vp_request=vp_request,
        vc_name=cred_name,
        always_hidden_keys=["linkSecret"],
    )
    return verifier.process_request(vp_response)



class TestVerifyVP:

    def test_valid_vp_verifies(self, issued_credential):
        """End-to-end: issue → build VP → verify VP."""
        holder, issuer, cred_name = issued_credential
        nonce = os.urandom(32)

        vp = holder.build_vp(
            revealed_keys=["name", "studentId"],
            nonce=nonce,
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )

        request = vp.prepare_verification_request(
            pub_key=issuer.public_key,
            nonce=nonce,
        )
        assert bbs.verify_proof(request) is True

    def test_vp_with_single_revealed_attribute(self, issued_credential):
        """Selective disclosure with only one attribute revealed."""
        holder, issuer, cred_name = issued_credential
        nonce = os.urandom(32)

        vp = holder.build_vp(
            revealed_keys=["age"],
            nonce=nonce,
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )

        request = vp.prepare_verification_request(
            pub_key=issuer.public_key,
            nonce=nonce,
        )
        assert bbs.verify_proof(request) is True
        assert vp.verifiableCredential["credentialSubject"] == {"age": "30"}

    def test_vp_with_all_revealable_attributes(self, issued_credential):
        """Revealing all non-enforced-hidden attributes still verifies."""
        holder, issuer, cred_name = issued_credential
        nonce = os.urandom(32)

        vp = holder.build_vp(
            revealed_keys=["name", "age", "studentId"],
            nonce=nonce,
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )

        request = vp.prepare_verification_request(
            pub_key=issuer.public_key,
            nonce=nonce,
        )
        assert bbs.verify_proof(request) is True

    def test_wrong_nonce_fails_verification(self, issued_credential):
        """Using a different nonce on the verifier side must fail."""
        holder, issuer, cred_name = issued_credential
        holder_nonce = os.urandom(32)
        wrong_nonce = os.urandom(32)

        vp = holder.build_vp(
            revealed_keys=["name"],
            nonce=holder_nonce,
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )

        request = vp.prepare_verification_request(
            pub_key=issuer.public_key,
            nonce=wrong_nonce,
        )
        assert bbs.verify_proof(request) is False

    def test_tampered_issuer_fails_verification(self, issued_credential):
        """Modifying the issuer in the VP envelope should break nonce-binding."""
        holder, issuer, cred_name = issued_credential
        nonce = os.urandom(32)

        vp = holder.build_vp(
            revealed_keys=["name"],
            nonce=nonce,
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )

        vp.verifiableCredential["issuer"] = "did:evil:attacker"

        request = vp.prepare_verification_request(
            pub_key=issuer.public_key,
            nonce=nonce,
        )
        assert bbs.verify_proof(request) is False

    def test_tampered_context_fails_verification(self, issued_credential):
        """Modifying the VP context should break nonce-binding."""
        holder, issuer, cred_name = issued_credential
        nonce = os.urandom(32)

        vp = holder.build_vp(
            revealed_keys=["name"],
            nonce=nonce,
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )

        vp.context.append("https://evil.com/context")

        request = vp.prepare_verification_request(
            pub_key=issuer.public_key,
            nonce=nonce,
        )
        assert bbs.verify_proof(request) is False

    def test_tampered_revealed_value_fails_verification(self, issued_credential):
        """Modifying a revealed attribute value in the VP should fail verification."""
        holder, issuer, cred_name = issued_credential
        nonce = os.urandom(32)

        vp = holder.build_vp(
            revealed_keys=["name"],
            nonce=nonce,
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )

        vp.verifiableCredential["credentialSubject"]["name"] = "Mallory"

        request = vp.prepare_verification_request(
            pub_key=issuer.public_key,
            nonce=nonce,
        )
        assert bbs.verify_proof(request) is False

    def test_wrong_issuer_public_key_fails(self, issued_credential):
        """Verifying against a different issuer's public key must fail."""
        holder, issuer, cred_name = issued_credential
        nonce = os.urandom(32)
        other_issuer = IssuerInstance()

        vp = holder.build_vp(
            revealed_keys=["name"],
            nonce=nonce,
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )

        request = vp.prepare_verification_request(
            pub_key=other_issuer.public_key,
            nonce=nonce,
        )
        assert bbs.verify_proof(request) is False

    def test_serialisation_roundtrip_preserves_verifiability(self, issued_credential):
        """VP should still verify after a JSON serialisation roundtrip."""
        holder, issuer, cred_name = issued_credential
        nonce = os.urandom(32)

        vp = holder.build_vp(
            revealed_keys=["name", "age"],
            nonce=nonce,
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )

        vp_restored = VerifiablePresentation.from_json(vp.to_json())

        request = vp_restored.prepare_verification_request(
            pub_key=issuer.public_key,
            nonce=nonce,
        )
        assert bbs.verify_proof(request) is True


# ═════════════════════════════════════════════════════════════════════
# Entity-API VP flow tests (VerifierInstance ↔ HolderInstance)
# ═════════════════════════════════════════════════════════════════════

class TestEntityVPFlow:
    """Happy-path flows through the full entity API."""

    def test_normal_flow(self, issued_credential):
        """Single end-to-end VP flow via entity APIs."""
        holder, issuer, cred_name = issued_credential
        valid, revealed, vp = _full_entity_flow(
            holder, issuer, cred_name, ["name", "studentId"]
        )
        assert valid is True
        assert revealed == {"name": "Alice", "studentId": "STU-2026-001"}
        assert isinstance(vp, VerifiablePresentation)

    def test_repeated_flow_1000_times(self, issued_credential):
        """The same credential can produce valid VPs repeatedly.
        Each iteration uses a fresh verifier challenge nonce."""
        holder, issuer, cred_name = issued_credential
        for _ in range(1000):
            valid, revealed, _ = _full_entity_flow(
                holder, issuer, cred_name, ["name"]
            )
            assert valid is True
            assert revealed == {"name": "Alice"}

    def test_single_revealed_attribute(self, issued_credential):
        """Minimal selective disclosure through entity APIs."""
        holder, issuer, cred_name = issued_credential
        valid, revealed, _ = _full_entity_flow(
            holder, issuer, cred_name, ["age"]
        )
        assert valid is True
        assert revealed == {"age": "30"}

    def test_all_revealable_attributes(self, issued_credential):
        """Disclosing every non-hidden attribute still verifies."""
        holder, issuer, cred_name = issued_credential
        valid, revealed, _ = _full_entity_flow(
            holder, issuer, cred_name, ["name", "age", "studentId"]
        )
        assert valid is True
        assert revealed == {
            "name": "Alice", "age": "30", "studentId": "STU-2026-001"
        }

    def test_serialisation_roundtrip(self, issued_credential):
        """VP survives JSON roundtrip and still verifies via entity API."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer])
        vp_request = verifier.presentation_request(["name", "age"])
        vp_response = holder.present_credential(
            vp_request=vp_request,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        # Roundtrip the VP through JSON
        vp_json = vp_response.vp.to_json()
        vp_restored = VerifiablePresentation.from_json(vp_json)
        restored_response = api.ForwardVPResponse(
            vp=vp_restored, pub_key=vp_response.pub_key
        )
        registry = RegistryInstance()
        valid, revealed, _ = _process_vp(verifier, registry, restored_response)
        assert valid is True
        assert revealed == {"name": "Alice", "age": "30"}


class TestEntityVPTampering:
    """Verification must fail when VP fields are tampered with after construction."""

    def test_tampered_issuer(self, issued_credential):
        """Changing the VC issuer in the VP breaks nonce-binding."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer])
        vp_request = verifier.presentation_request(["name"])
        vp_response = holder.present_credential(
            vp_request=vp_request, vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        vp_response.vp.verifiableCredential["issuer"] = "did:evil:attacker"
        registry = RegistryInstance()
        valid, revealed, _ = _process_vp(verifier, registry, vp_response)
        assert valid is False
        assert revealed is None

    def test_tampered_vp_context(self, issued_credential):
        """Injecting an extra VP-level context breaks nonce-binding."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer])
        vp_request = verifier.presentation_request(["name"])
        vp_response = holder.present_credential(
            vp_request=vp_request, vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        vp_response.vp.context.append("https://evil.com/ctx")
        registry = RegistryInstance()
        valid, _, _ = _process_vp(verifier, registry, vp_response)
        assert valid is False

    def test_tampered_vc_context(self, issued_credential):
        """Modifying the embedded VC @context breaks nonce-binding."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer])
        vp_request = verifier.presentation_request(["name"])
        vp_response = holder.present_credential(
            vp_request=vp_request, vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        vp_response.vp.verifiableCredential["@context"].append("https://evil.com")
        registry = RegistryInstance()
        valid, _, _ = _process_vp(verifier, registry, vp_response)
        assert valid is False

    def test_tampered_vc_type(self, issued_credential):
        """Modifying the embedded VC type breaks nonce-binding."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer])
        vp_request = verifier.presentation_request(["name"])
        vp_response = holder.present_credential(
            vp_request=vp_request, vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        vp_response.vp.verifiableCredential["type"].append("FakeType")
        registry = RegistryInstance()
        valid, _, _ = _process_vp(verifier, registry, vp_response)
        assert valid is False

    def test_tampered_vp_type(self, issued_credential):
        """Modifying the VP-level type breaks nonce-binding."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer])
        vp_request = verifier.presentation_request(["name"])
        vp_response = holder.present_credential(
            vp_request=vp_request, vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        vp_response.vp.type.append("EvilPresentation")
        registry = RegistryInstance()
        valid, _, _ = _process_vp(verifier, registry, vp_response)
        assert valid is False

    def test_tampered_revealed_value(self, issued_credential):
        """Modifying a disclosed attribute value fails cryptographic verification."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer])
        vp_request = verifier.presentation_request(["name"])
        vp_response = holder.present_credential(
            vp_request=vp_request, vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        vp_response.vp.verifiableCredential["credentialSubject"]["name"] = "Mallory"
        registry = RegistryInstance()
        valid, revealed, _ = _process_vp(verifier, registry, vp_response)
        assert valid is False
        assert revealed is None

    def test_tampered_attribute_order(self, issued_credential):
        """Reordering credentialSubject keys breaks proof verification
        because BBS+ proofs are index-sensitive."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer])
        vp_request = verifier.presentation_request(["name", "studentId"])
        vp_response = holder.present_credential(
            vp_request=vp_request, vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        # Reverse the key order in credentialSubject
        subject = vp_response.vp.verifiableCredential["credentialSubject"]
        reversed_subject = dict(reversed(list(subject.items())))
        vp_response.vp.verifiableCredential["credentialSubject"] = reversed_subject
        registry = RegistryInstance()
        valid, _, _ = _process_vp(verifier, registry, vp_response)
        assert valid is False


class TestEntityVPNonce:
    """Nonce-related verification failures."""

    def test_wrong_nonce_fails(self, issued_credential):
        """VP built with a different nonce than the verifier's challenge fails."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer])
        vp_request = verifier.presentation_request(["name"])
        # Build VP with a rogue nonce instead of the verifier's
        rogue_nonce = os.urandom(32)
        vp = holder.build_vp(
            revealed_keys=["name"],
            nonce=rogue_nonce,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        rogue_response = api.ForwardVPResponse(
            vp=vp, pub_key=issuer.public_key
        )
        registry = RegistryInstance()
        valid, _, _ = _process_vp(verifier, registry, rogue_response)
        assert valid is False

    def test_replay_attack_fails(self, issued_credential):
        """Replaying a VP from a previous session with a new verifier
        challenge must fail, even if requested attributes are identical."""
        holder, issuer, cred_name = issued_credential

        # First session — legitimate
        verifier1 = VerifierInstance()
        _sync_verifier(verifier1, [issuer])
        vp_request1 = verifier1.presentation_request(["name"])
        vp_response1 = holder.present_credential(
            vp_request=vp_request1, vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        registry = RegistryInstance()
        valid1, _, _ = _process_vp(verifier1, registry, vp_response1)
        assert valid1 is True

        # Second session — attacker replays vp_response1
        verifier2 = VerifierInstance()
        _sync_verifier(verifier2, [issuer])
        _vp_request2 = verifier2.presentation_request(["name"])
        registry = RegistryInstance()
        valid2, _, _ = _process_vp(verifier2, registry, vp_response1)
        assert valid2 is False


class TestEntityVPWrongKey:
    """Issuer public key mismatch."""

    def test_wrong_issuer_key_fails(self, issued_credential):
        """VP verified against a different issuer's key must fail."""
        holder, issuer, cred_name = issued_credential
        other_issuer = IssuerInstance()

        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer, other_issuer])
        vp_request = verifier.presentation_request(["name"])
        vp_response = holder.present_credential(
            vp_request=vp_request, vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        # Swap the pub_key to a different issuer's
        vp_response.pub_key = other_issuer.public_key
        registry = RegistryInstance()
        valid, _, _ = _process_vp(verifier, registry, vp_response)
        assert valid is False


class TestEntityVPMissingAttributes:
    """Verifier rejects VPs that don't satisfy the request."""

    def test_missing_requested_attributes_fails(self, issued_credential):
        """If the VP doesn't contain all requested attributes,
        verification fails at the attribute-completeness phase."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer])
        vp_request = verifier.presentation_request(["name", "studentId"])
        # Build a VP that only reveals "name" (not "studentId")
        vp = holder.build_vp(
            revealed_keys=["name"],
            nonce=vp_request.nonce,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        partial_response = api.ForwardVPResponse(
            vp=vp, pub_key=issuer.public_key
        )
        registry = RegistryInstance()
        valid, revealed, _ = _process_vp(verifier, registry, partial_response)
        assert valid is False
        assert revealed is None


