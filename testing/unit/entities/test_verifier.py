import pytest
import os
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.exceptions.exceptions import VerifierNotInInteraction, VerifierStateError
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

    # Issuance flow
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

class TestEntityVerifierStateGuards:
    """Verifier state machine guards."""

    def test_process_request_without_challenge_raises(self, issued_credential):
        """Verifier rejects a VP when no challenge has been issued."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        # Build a VP without going through verifier.presentation_request
        vp = holder.build_vp(
            revealed_keys=["name"],
            nonce=os.urandom(32),
            issuer_pub_key=issuer.public_key,
            vc_name=cred_name,
            always_hidden_keys=["linkSecret"],
        )
        response = api.ForwardVPResponse(vp=vp, pub_key=issuer.public_key)
        _sync_verifier(verifier, [issuer])
        with pytest.raises(VerifierNotInInteraction):
            verifier.process_request(response)

    def test_double_presentation_request_raises(self, issued_credential):
        """Verifier rejects a second challenge while one is pending."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        verifier.presentation_request(["name"])
        with pytest.raises(VerifierStateError):
            verifier.presentation_request(["age"])

    def test_verifier_resets_after_verification(self, issued_credential):
        """After processing a VP, the verifier can issue a new challenge."""
        holder, issuer, cred_name = issued_credential

        # First flow
        valid, _, _ = _full_entity_flow(
            holder, issuer, cred_name, ["name"]
        )
        assert valid is True

        # Second flow with different attributes — verifier must be reset
        valid2, revealed2, _ = _full_entity_flow(
            holder, issuer, cred_name, ["age", "studentId"]
        )
        assert valid2 is True
        assert revealed2 == {"age": "30", "studentId": "STU-2026-001"}
