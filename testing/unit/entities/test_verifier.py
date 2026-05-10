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
def registry():
    return RegistryInstance()

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


def _sync_verifier(verifier, issuers: list, registry: RegistryInstance):
    """Helper: registers issuers and syncs verifier cache."""
    for issuer in issuers:
        reg_req = issuer.register_issuer()
        reg_resp = registry.process_request(reg_req)
        issuer.process_request(reg_resp)
    
    bulk_req = verifier.fetch_all_issuer_details()
    bulk_resp = registry.process_request(bulk_req)
    verifier.process_request(bulk_resp)


def _full_entity_flow(holder, issuer, cred_name, requested_attrs, registry: RegistryInstance):
    """Helper: runs the VP entity flow and returns the verifier result tuple."""
    verifier = VerifierInstance()
    _sync_verifier(verifier, [issuer], registry)
    vp_request = verifier.presentation_request(requested_attributes=requested_attrs)
    vp_response = holder.present_credential(
        vp_request=vp_request,
        vc_name=cred_name,
        always_hidden_keys=["linkSecret"],
    )
    return verifier.process_request(vp_response)

class TestEntityVerifierStateGuards:
    """Verifier state machine guards."""

    def test_process_request_without_challenge_raises(self, issued_credential, registry):
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
        _sync_verifier(verifier, [issuer], registry)
        with pytest.raises(VerifierNotInInteraction):
            verifier.process_request(response)

    def test_double_presentation_request_raises(self, issued_credential):
        """Verifier rejects a second challenge while one is pending."""
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        verifier.presentation_request(["name"])
        with pytest.raises(VerifierStateError):
            verifier.presentation_request(["age"])

    def test_verifier_resets_after_verification(self, issued_credential, registry):
        """After processing a VP, the verifier can issue a new challenge."""
        holder, issuer, cred_name = issued_credential

        # First flow
        valid, _, _ = _full_entity_flow(
            holder, issuer, cred_name, ["name"], registry
        )
        assert valid is True

        # Second flow with different attributes — verifier must be reset
        valid2, revealed2, _ = _full_entity_flow(
            holder, issuer, cred_name, ["age", "studentId"], registry
        )
        assert valid2 is True
        assert revealed2 == {"age": "30", "studentId": "STU-2026-001"}

from datetime import timedelta, timezone
from datetime import datetime as dt
from bbs_iss.exceptions.exceptions import MissingAttributeError

class TestVerifierValidityCheck:
    """High-level validity checks (expiration, revocation)."""

    def test_check_validity_success(self, issued_credential, registry):
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer], registry)
        
        # Disclose expiration and revocation
        valid, _, vp = _full_entity_flow(holder, issuer, cred_name, ["name", "validUntil", "revocationMaterial"], registry)
        assert valid is True
        
        # Check validity (default: only expiration)
        assert verifier.check_validity(vp) is True
        
        # Check validity with revocation
        assert verifier.check_validity(vp, with_bit_index=True) is True

    def test_check_validity_expired(self, issued_credential, registry):
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer], registry)
        
        valid, _, vp = _full_entity_flow(holder, issuer, cred_name, ["name", "validUntil"], registry)
        assert valid is True
        
        # Mock future date: 1 year from now
        future_date = dt.now(timezone.utc) + timedelta(days=365)
        assert verifier.check_validity(vp, current_date=future_date) is False

    def test_check_validity_revoked(self, issued_credential, registry):
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer], registry)
        
        valid, revealed, vp = _full_entity_flow(holder, issuer, cred_name, ["name", "revocationMaterial", "validUntil"], registry)
        assert valid is True
        
        # Revoke the credential
        idx_hex = revealed["revocationMaterial"]
        issuer.revoke_index(idx_hex)
        
        # Registry update and Verifier sync
        reg_req = issuer.update_issuer_details()
        reg_resp = registry.process_request(reg_req)
        issuer.process_request(reg_resp)
        
        bulk_req = verifier.fetch_all_issuer_details()
        bulk_resp = registry.process_request(bulk_req)
        verifier.process_request(bulk_resp)
        
        # Validity check should now fail for revocation
        assert verifier.check_validity(vp, with_bit_index=True) is False
        # But still pass for expiration only
        assert verifier.check_validity(vp, with_bit_index=False) is True

    def test_check_validity_missing_attributes(self, issued_credential, registry):
        holder, issuer, cred_name = issued_credential
        verifier = VerifierInstance()
        _sync_verifier(verifier, [issuer], registry)
        
        # Case 1: Missing validUntil
        valid, _, vp = _full_entity_flow(holder, issuer, cred_name, ["name"], registry)
        assert valid is True
        with pytest.raises(MissingAttributeError, match="validUntil"):
            verifier.check_validity(vp)
            
        # Case 2: Missing revocationMaterial when requested
        valid, _, vp = _full_entity_flow(holder, issuer, cred_name, ["name", "validUntil"], registry)
        assert valid is True
        with pytest.raises(MissingAttributeError, match="revocationMaterial"):
            verifier.check_validity(vp, with_bit_index=True)
