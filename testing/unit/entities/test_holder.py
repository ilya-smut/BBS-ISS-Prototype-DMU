import pytest
import os
import ursa_bbs_signatures as bbs
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.interfaces.credential import VerifiableCredential, VerifiablePresentation
from bbs_iss.exceptions.exceptions import HolderNotInInteraction, HolderStateError
import bbs_iss.interfaces.requests_api as api
from bbs_iss.utils.utils import gen_link_secret

@pytest.fixture
def issued_credential():
    issuer = IssuerInstance()
    holder = HolderInstance()

    attributes = api.IssuanceAttributes()
    attributes.append("name", "Alice", api.AttributeType.REVEALED)
    attributes.append("age", "30", api.AttributeType.REVEALED)
    attributes.append("studentId", "STU-2026-001", api.AttributeType.REVEALED)
    attributes.append("linkSecret", gen_link_secret(), api.AttributeType.HIDDEN)

    cred_name = "student-card"

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
    holder.process_request(forward_vc)

    return holder, issuer, cred_name


class TestBuildVP:

    def test_build_vp_returns_vp_with_proof(self, issued_credential):
        holder, issuer, cred_name = issued_credential
        nonce = os.urandom(32)

        vp = holder.build_vp(
            revealed_keys=["name", "studentId"],
            nonce=nonce,
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )

        assert isinstance(vp, VerifiablePresentation)
        assert vp.verifiableCredential["proof"] is not None
        assert isinstance(vp.verifiableCredential["proof"], bytes)

    def test_vp_contains_only_revealed_attributes(self, issued_credential):
        holder, issuer, cred_name = issued_credential
        nonce = os.urandom(32)

        vp = holder.build_vp(
            revealed_keys=["name"],
            nonce=nonce,
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )

        subject = vp.verifiableCredential["credentialSubject"]
        assert "name" in subject
        assert subject["name"] == "Alice"
        assert "age" not in subject
        assert "studentId" not in subject
        assert "linkSecret" not in subject
        assert VerifiableCredential.META_HASH_KEY not in subject


class TestEntityVPHolderGuards:
    """Holder-side validation in present_credential."""

    def test_hidden_key_conflict_raises(self, issued_credential):
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        vp_request = verifier.presentation_request(["linkSecret", "name"])
        with pytest.raises(ValueError, match="conflict with enforced-hidden"):
            holder.present_credential(
                vp_request=vp_request, vc_name=cred_name,
                always_hidden_keys=["linkSecret"],
            )

    def test_metahash_conflict_raises(self, issued_credential):
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        vp_request = verifier.presentation_request(["metaHash", "name"])
        with pytest.raises(ValueError, match="conflict with enforced-hidden"):
            holder.present_credential(
                vp_request=vp_request, vc_name=cred_name,
            )

    def test_nonexistent_credential_raises(self, issued_credential):
        holder, issuer, _ = issued_credential
        verifier = VerifierInstance()
        vp_request = verifier.presentation_request(["name"])
        with pytest.raises(ValueError, match="not found"):
            holder.present_credential(
                vp_request=vp_request, vc_name="does-not-exist",
            )

    def test_unavailable_attribute_raises(self, issued_credential):
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        vp_request = verifier.presentation_request(["email"])
        with pytest.raises(ValueError, match="missing requested attributes"):
            holder.present_credential(
                vp_request=vp_request, vc_name=cred_name,
                always_hidden_keys=["linkSecret"],
            )


def test_holder_rejects_out_of_order_responses():
    """Assert HolderStateError/HolderNotInInteraction when receiving responses out of order."""
    holder = HolderInstance()
    
    # Receiving a freshness response without an active issuance
    fake_freshness = api.FreshnessUpdateResponse(nonce=b"1234")
    with pytest.raises(HolderNotInInteraction):
        holder.process_request(fake_freshness)
        
    issuer = IssuerInstance()
    attr = api.IssuanceAttributes()
    attr.append("test", "test", api.AttributeType.REVEALED)
    attr.append("secret", "test", api.AttributeType.HIDDEN)
    issuer_name = "Mock-Issuer"
    data = api.IssuerPublicData(issuer_name, issuer.public_key, "0"*10, 52, 7)
    holder.public_data_cache.update(issuer_name, data)
    holder.issuance_request(issuer_name, attr, "c1")
    
    # Now in interaction, but receiving a ForwardVC instead of Freshness
    fake_vc_resp = api.ForwardVCResponse(vc=VerifiableCredential(issuer="test", credential_subject={}))
    with pytest.raises(HolderStateError):
        holder.process_request(fake_vc_resp)
