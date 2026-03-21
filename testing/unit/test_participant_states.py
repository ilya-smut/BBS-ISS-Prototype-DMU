import pytest
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
import bbs_iss.interfaces.requests_api as api
from bbs_iss.exceptions.exceptions import IssuerNotAvailable, HolderStateError, HolderNotInInteraction, ProofValidityError

def test_issuer_rejects_overlapping_sessions():
    """Assert IssuerNotAvailable is raised if an ISSUANCE request arrives while busy."""
    issuer = IssuerInstance()
    holder1 = HolderInstance()
    holder2 = HolderInstance()
    
    attr = api.IssuanceAttributes()
    attr.append("test", "test", api.AttributeType.REVEALED)
    attr.append("secret", "test", api.AttributeType.HIDDEN)
    
    req1 = holder1.issuance_request(issuer.public_key, attr, "c1")
    req2 = holder2.issuance_request(issuer.public_key, attr, "c2")
    
    # First request succeeds and makes issuer busy
    issuer.process_request(req1)
    
    # Second request should fail
    with pytest.raises(IssuerNotAvailable):
        issuer.process_request(req2)

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
    holder.issuance_request(issuer.public_key, attr, "c1")
    
    # Now in interaction, but receiving a ForwardVC instead of Freshness
    from bbs_iss.interfaces.credential import VerifiableCredential
    fake_vc_resp = api.ForwardVCResponse(vc=VerifiableCredential(issuer="test", credential_subject={}))
    with pytest.raises(HolderStateError):
        holder.process_request(fake_vc_resp)


def test_issuer_rejects_replayed_proof():
    """Assert ProofValidityError is raised when a valid proof from a different session (different nonce) is replayed."""
    issuer = IssuerInstance()
    
    # Session 1
    holder1 = HolderInstance()
    attr1 = api.IssuanceAttributes()
    attr1.append("secret", "test", api.AttributeType.HIDDEN)
    attr1.append("test", "test", api.AttributeType.REVEALED)
    
    req1 = holder1.issuance_request(issuer.public_key, attr1, "c1")
    freshness1 = issuer.process_request(req1)
    valid_blind_req1 = holder1.process_request(freshness1)
    
    issuer2 = IssuerInstance()
    holder2 = HolderInstance()
    attr2 = api.IssuanceAttributes()
    attr2.append("test", "tampered", api.AttributeType.HIDDEN)
    req2 = holder2.issuance_request(issuer2.public_key, attr2, "c2")
    freshness2 = issuer2.process_request(req2)
    valid_blind_req2 = holder2.process_request(freshness2)

    # Tamper with Session 1's request by injecting Session 2's perfectly well-formed,
    # but cryptographically mismatched proof.
    import copy
    invalid_blind_req = copy.copy(valid_blind_req1)
    invalid_blind_req.proof = valid_blind_req2.proof
    
    with pytest.raises(ProofValidityError):
        issuer.process_request(invalid_blind_req)
