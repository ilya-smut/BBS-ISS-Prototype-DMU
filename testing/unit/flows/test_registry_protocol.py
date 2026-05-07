import pytest
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
import bbs_iss.interfaces.requests_api as api
from bbs_iss.exceptions.exceptions import IssuerStateError, HolderStateError, VerifierStateError

def test_issuer_registration_flow():
    issuer = IssuerInstance()
    issuer.issuer_parameters = {"issuer": "Alpha-Issuer"}
    registry = RegistryInstance()
    
    # Initiation
    reg_req = issuer.register_issuer()
    assert not issuer.state.available
    
    # Registry Processing
    resp = registry.process_request(reg_req)
    
    # Finalization
    success = issuer.process_request(resp)
    assert success is True
    assert issuer.state.available
    assert issuer.issuer_parameters["issuer"] == "Alpha-Issuer"

def test_holder_lazy_lookup_flow():
    registry = RegistryInstance()
    issuer = IssuerInstance()
    issuer.issuer_parameters = {"issuer": "Mock"}
    registry.process_request(issuer.register_issuer())
    
    holder = HolderInstance()
    assert holder.public_data_cache.get("Mock") is None
    
    # Miss -> Generates request
    req = holder.get_issuer_details("Mock")
    assert isinstance(req, api.GetIssuerDetailsRequest)
    assert holder.state.awaiting
    
    # Response
    resp = registry.process_request(req)
    holder.process_request(resp)
    
    # Hit -> Returns data immediately
    assert not holder.state.awaiting
    data = holder.get_issuer_details("Mock")
    assert isinstance(data, api.IssuerPublicData)
    assert data.issuer_name == "Mock"

def test_verifier_bulk_sync_flow():
    registry = RegistryInstance()
    
    i1 = IssuerInstance()
    i1.issuer_parameters = {"issuer": "I1"}
    registry.process_request(i1.register_issuer())
    
    i2 = IssuerInstance()
    i2.issuer_parameters = {"issuer": "I2"}
    registry.process_request(i2.register_issuer())
    
    verifier = VerifierInstance()
    req = verifier.fetch_all_issuer_details()
    assert isinstance(req, api.BulkGetIssuerDetailsRequest)
    
    resp = registry.process_request(req)
    verifier.process_request(resp)
    
    assert verifier.public_data_cache.get("I1") is not None
    assert verifier.public_data_cache.get("I2") is not None

def test_holder_rejects_unsolicited_registry_response():
    holder = HolderInstance()
    resp = api.IssuerDetailsResponse(issuer_data=None)
    
    from bbs_iss.exceptions.exceptions import HolderNotInInteraction
    with pytest.raises(HolderNotInInteraction):
        holder.process_request(resp)

def test_issuer_rejects_wrong_registry_response():
    issuer = IssuerInstance()
    issuer.issuer_parameters = {"issuer": "Alpha"}
    # Issuer is awaiting registration
    issuer.register_issuer()
    
    wrong_resp = api.IssuerDetailsResponse(issuer_data=api.IssuerPublicData("Beta", api.PublicKeyBLS(b"k"), "0", 1, 1))
    
    # Returns False instead of raising IssuerStateError because state IS ready for a response, 
    # just the data is wrong.
    assert issuer.process_request(wrong_resp) is False
    assert issuer.state.available
