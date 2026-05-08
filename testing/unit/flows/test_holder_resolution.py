import pytest
import os
import bbs_iss.interfaces.requests_api as api
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.exceptions.exceptions import UnregisteredIssuerError
from bbs_iss.utils.utils import gen_link_secret

@pytest.fixture
def setup_entities():
    holder = HolderInstance()
    issuer = IssuerInstance()
    registry = RegistryInstance()
    
    # Register issuer in registry
    reg_req = issuer.register_issuer()
    reg_resp = registry.process_request(reg_req)
    issuer.process_request(reg_resp)
    
    issuer_name = issuer.issuer_parameters["issuer"] if issuer.issuer_parameters else "Mock-Issuer"
    
    return holder, issuer, registry, issuer_name

def test_holder_resolution_on_issuance(setup_entities):
    holder, issuer, registry, issuer_name = setup_entities
    
    attributes = api.IssuanceAttributes()
    attributes.append("name", "Alice", api.AttributeType.REVEALED)
    attributes.append("linkSecret", gen_link_secret(), api.AttributeType.HIDDEN)
    
    # 1. Holder starts issuance_request (cache is empty)
    # It should return a GetIssuerDetailsRequest
    res = holder.issuance_request(issuer_name, attributes, "my-cred")
    assert isinstance(res, api.GetIssuerDetailsRequest)
    assert res.issuer_name == issuer_name
    assert holder.state.pending_issuer_name == issuer_name
    assert holder.state.original_request == api.RequestType.ISSUANCE
    
    # 2. Sync with registry
    resp = registry.process_request(res)
    
    # 3. Holder processes registry response
    # It should resume and return VCIssuanceRequest
    res2 = holder.process_request(resp)
    assert isinstance(res2, api.VCIssuanceRequest)
    assert holder.state.issuer_pub_key == issuer.public_key
    assert holder.state.pending_issuer_name is None
    
    # 4. Continue standard issuance flow
    freshness = issuer.process_request(res2)
    blind_req = holder.process_request(freshness)
    forward_vc = issuer.process_request(blind_req)
    valid = holder.process_request(forward_vc)
    
    assert valid is True
    assert "my-cred" in holder.credentials

def test_holder_resolution_failure(setup_entities):
    holder, issuer, registry, issuer_name = setup_entities
    
    attributes = api.IssuanceAttributes()
    attributes.append("name", "Alice", api.AttributeType.REVEALED)
    
    # 1. Start issuance for UNREGISTERED issuer
    res = holder.issuance_request("Unknown-Issuer", attributes, "fail-cred")
    assert isinstance(res, api.GetIssuerDetailsRequest)
    
    # 2. Registry returns empty response
    resp = registry.process_request(res)
    assert resp.issuer_data is None
    
    # 3. Holder should raise UnregisteredIssuerError
    with pytest.raises(UnregisteredIssuerError, match="not found in registry"):
        holder.process_request(resp)
    
    # 4. State should be reset
    assert not holder.state.awaiting
    assert holder.state.pending_issuer_name is None

def test_holder_resolution_cache_hit(setup_entities):
    holder, issuer, registry, issuer_name = setup_entities
    
    # Pre-populate cache
    data = api.IssuerPublicData(
        issuer_name=issuer_name,
        public_key=issuer.public_key,
        revocation_bitstring="0"*10,
        valid_until_weeks=52,
        validity_window_days=7
    )
    holder.public_data_cache.update(issuer_name, data)
    
    attributes = api.IssuanceAttributes()
    attributes.append("name", "Alice", api.AttributeType.REVEALED)
    
    # issuance_request should return VCIssuanceRequest immediately
    res = holder.issuance_request(issuer_name, attributes, "cache-cred")
    assert isinstance(res, api.VCIssuanceRequest)
    assert holder.state.issuer_pub_key == issuer.public_key
