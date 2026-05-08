import pytest
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
import bbs_iss.interfaces.requests_api as api

def test_successful_issuance():
    """Execute the 4-step sequence resulting in a successfully verified credential.
    Run 500 rounds to ensure stability and correctness over multiple iterations.
    """
    issuer = IssuerInstance()
    
    for _ in range(500):
        holder = HolderInstance()
        attributes = api.IssuanceAttributes()
        attributes.append("name", "Alice", api.AttributeType.REVEALED)
        attributes.append("age", "30", api.AttributeType.REVEALED)
        attributes.append("ssn", "123-456-7890", api.AttributeType.HIDDEN)
        attributes.append("license", "XYZ-123", api.AttributeType.HIDDEN)

        # Step 1: Issuance Request
        # Pre-populate cache to simulate already resolved issuer
        issuer_name = "Mock-Issuer"
        data = api.IssuerPublicData(issuer_name, issuer.public_key, "0"*10, 52, 7)
        holder.public_data_cache.update(issuer_name, data)
        
        init_req = holder.issuance_request(
            issuer_name=issuer_name,
            attributes=attributes,
            cred_name="id-doc"
        )
        
        # Step 2: Freshness Response
        freshness_resp = issuer.process_request(init_req)
        
        # Step 3: Blind Sign Request
        blind_sign_req = holder.process_request(freshness_resp)
        
        # Step 4: Forward VC Response
        forward_vc_resp = issuer.process_request(blind_sign_req)
        
        # Holder unblinds and verifies
        is_valid = holder.process_request(forward_vc_resp)
        
        assert is_valid is True
        assert "id-doc" in holder.credentials
        
def test_concurrent_issuance_separation():
    """Ensure multiple interactions across different issuers/holders do not leak state or freshness nonces."""
    issuer1 = IssuerInstance()
    issuer2 = IssuerInstance()
    holder1 = HolderInstance()
    holder2 = HolderInstance()
    
    attr1 = api.IssuanceAttributes()
    attr1.append("name", "Alice", api.AttributeType.REVEALED)
    attr1.append("secret", "A", api.AttributeType.HIDDEN)
    
    attr2 = api.IssuanceAttributes()
    attr2.append("name", "Bob", api.AttributeType.REVEALED)
    attr2.append("secret", "B", api.AttributeType.HIDDEN)
    
    # Pre-populate cache for both
    data1 = api.IssuerPublicData("Issuer1", issuer1.public_key, "0"*10, 52, 7)
    holder1.public_data_cache.update("Issuer1", data1)
    data2 = api.IssuerPublicData("Issuer2", issuer2.public_key, "0"*10, 52, 7)
    holder2.public_data_cache.update("Issuer2", data2)
    
    req1 = holder1.issuance_request("Issuer1", attr1, "cred1")
    req2 = holder2.issuance_request("Issuer2", attr2, "cred2")
    
    fresh1 = issuer1.process_request(req1)
    fresh2 = issuer2.process_request(req2)
    
    assert fresh1.nonce != fresh2.nonce
    
    blind1 = holder1.process_request(fresh1)
    blind2 = holder2.process_request(fresh2)
    
    vc1 = issuer1.process_request(blind1)
    vc2 = issuer2.process_request(blind2)
    
    assert holder1.process_request(vc1) is True
    assert holder2.process_request(vc2) is True
