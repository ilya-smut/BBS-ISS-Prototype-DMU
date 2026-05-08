import pytest
import os
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
import bbs_iss.interfaces.requests_api as api
from bbs_iss.utils.utils import gen_link_secret

@pytest.fixture
def setup_entities():
    issuer = IssuerInstance()
    holder = HolderInstance()
    verifier = VerifierInstance()
    registry = RegistryInstance()
    
    # Register issuer in registry
    reg_req = issuer.register_issuer()
    reg_resp = registry.process_request(reg_req)
    issuer.process_request(reg_resp)
    
    issuer_name = issuer.issuer_parameters["issuer"] if issuer.issuer_parameters else "Mock-Issuer"
    
    return holder, issuer, verifier, registry, issuer_name

def test_verifier_resolution_on_cache_miss(setup_entities):
    holder, issuer, verifier, registry, issuer_name = setup_entities
    
    # 1. Issue a credential
    attributes = api.IssuanceAttributes()
    attributes.append("name", "Alice", api.AttributeType.REVEALED)
    attributes.append("linkSecret", gen_link_secret(), api.AttributeType.HIDDEN)
    
    init_req = holder.issuance_request(issuer_name, attributes, "my-cred")
    if isinstance(init_req, api.GetIssuerDetailsRequest):
        reg_resp = registry.process_request(init_req)
        init_req = holder.process_request(reg_resp)
        
    freshness = issuer.process_request(init_req)
    blind_req = holder.process_request(freshness)
    forward_vc = issuer.process_request(blind_req)
    holder.process_request(forward_vc)
    
    # 2. Verifier requests VP
    vp_request = verifier.presentation_request(["name"])
    
    # 3. Holder presents VP
    forward_vp = holder.present_credential(vp_request, "my-cred", always_hidden_keys=["linkSecret"])
    
    # 4. Verifier processes FORWARD_VP (cache is empty)
    # It should return a GetIssuerDetailsRequest
    res = verifier.process_request(forward_vp)
    assert isinstance(res, api.GetIssuerDetailsRequest)
    assert res.issuer_name == issuer_name
    assert verifier.state.queued_response == forward_vp
    assert verifier.state.type == api.RequestType.GET_ISSUER_DETAILS
    
    # 5. Registry processes the request
    details_resp = registry.process_request(res)
    
    # 6. Verifier processes ISSUER_DETAILS_RESPONSE
    # It should automatically resolve the queued VP and return successful verification
    final_res = verifier.process_request(details_resp)
    
    assert isinstance(final_res, tuple)
    valid, revealed, _ = final_res
    assert valid is True
    assert revealed == {"name": "Alice"}
    assert verifier.state.queued_response is None
    assert not verifier.state.awaiting

def test_verifier_resolution_on_key_mismatch(setup_entities):
    holder, issuer, verifier, registry, issuer_name = setup_entities
    
    # 1. Issue a credential
    attributes = api.IssuanceAttributes()
    attributes.append("name", "Alice", api.AttributeType.REVEALED)
    attributes.append("linkSecret", gen_link_secret(), api.AttributeType.HIDDEN)
    
    init_req = holder.issuance_request(issuer_name, attributes, "my-cred")
    if isinstance(init_req, api.GetIssuerDetailsRequest):
        reg_resp = registry.process_request(init_req)
        init_req = holder.process_request(reg_resp)
        
    freshness = issuer.process_request(init_req)
    blind_req = holder.process_request(freshness)
    forward_vc = issuer.process_request(blind_req)
    holder.process_request(forward_vc)
    
    # 2. Verifier has WRONG key in cache
    stale_data = api.IssuerPublicData(
        issuer_name=issuer_name,
        public_key=api.PublicKeyBLS(os.urandom(96)), # Wrong key
        revocation_bitstring="0"*10,
        valid_until_weeks=52,
        validity_window_days=7
    )
    verifier.public_data_cache.update(issuer_name, stale_data)
    
    # 3. Verifier requests VP
    vp_request = verifier.presentation_request(["name"])
    
    # 4. Holder presents VP (with CORRECT key in ForwardVPResponse)
    forward_vp = holder.present_credential(vp_request, "my-cred", always_hidden_keys=["linkSecret"])
    
    # 5. Verifier processes FORWARD_VP
    # Key mismatch -> should trigger resolution
    res = verifier.process_request(forward_vp)
    assert isinstance(res, api.GetIssuerDetailsRequest)
    
    # 6. Registry processes the request (returns CORRECT data)
    details_resp = registry.process_request(res)
    
    # 7. Verifier processes response
    final_res = verifier.process_request(details_resp)
    valid, revealed, _ = final_res
    assert valid is True
    assert revealed == {"name": "Alice"}

def test_verifier_resolution_failure(setup_entities):
    holder, issuer, verifier, registry, issuer_name = setup_entities
    
    # 1. Issue a credential
    attributes = api.IssuanceAttributes()
    attributes.append("name", "Alice", api.AttributeType.REVEALED)
    attributes.append("linkSecret", gen_link_secret(), api.AttributeType.HIDDEN)
    
    init_req = holder.issuance_request(issuer_name, attributes, "my-cred")
    if isinstance(init_req, api.GetIssuerDetailsRequest):
        reg_resp = registry.process_request(init_req)
        init_req = holder.process_request(reg_resp)
        
    freshness = issuer.process_request(init_req)
    blind_req = holder.process_request(freshness)
    forward_vc = issuer.process_request(blind_req)
    holder.process_request(forward_vc)
    
    # 2. Verifier requests VP
    vp_request = verifier.presentation_request(["name"])
    
    # 3. Holder presents VP
    forward_vp = holder.present_credential(vp_request, "my-cred", always_hidden_keys=["linkSecret"])
    
    # 4. Verifier processes FORWARD_VP -> returns request
    res = verifier.process_request(forward_vp)
    
    # 5. Registry returns NONE (issuer not found)
    details_resp = api.IssuerDetailsResponse(issuer_data=None)
    
    # 6. Verifier processes response -> should fail verification
    final_res = verifier.process_request(details_resp)
    valid, revealed, _ = final_res
    assert valid is False
    assert revealed is None
    assert verifier.state.queued_response is None
    assert not verifier.state.awaiting
