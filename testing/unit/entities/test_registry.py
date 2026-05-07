import pytest
from bbs_iss.entities.registry import RegistryInstance
import bbs_iss.interfaces.requests_api as api

def test_registry_registration_and_get():
    registry = RegistryInstance()
    pk = api.PublicKeyBLS(b"key1")
    data = api.IssuerPublicData("Issuer1", pk, "0", 7, 7)
    
    # Registration
    reg_req = api.RegisterIssuerDetailsRequest("Issuer1", data)
    resp = registry.process_request(reg_req)
    assert resp.issuer_data == data
    
    # Get
    get_req = api.GetIssuerDetailsRequest("Issuer1")
    resp_get = registry.process_request(get_req)
    assert resp_get.issuer_data == data

def test_registry_registration_conflict():
    registry = RegistryInstance()
    pk1 = api.PublicKeyBLS(b"key1")
    pk2 = api.PublicKeyBLS(b"key2")
    data1 = api.IssuerPublicData("I1", pk1, "0", 7, 7)
    data2 = api.IssuerPublicData("I1", pk2, "1", 1, 1)
    
    registry.process_request(api.RegisterIssuerDetailsRequest("I1", data1))
    
    # Attempting to register same name with different data
    resp = registry.process_request(api.RegisterIssuerDetailsRequest("I1", data2))
    assert resp.issuer_data == data1 # Returns existing data
    assert resp.issuer_data != data2

def test_registry_update():
    registry = RegistryInstance()
    pk1 = api.PublicKeyBLS(b"key1")
    data1 = api.IssuerPublicData("I1", pk1, "0", 7, 7)
    registry.process_request(api.RegisterIssuerDetailsRequest("I1", data1))
    
    # Valid update
    data2 = api.IssuerPublicData("I1", pk1, "1", 5, 5)
    upd_req = api.UpdateIssuerDetailsRequest("I1", data2)
    resp = registry.process_request(upd_req)
    assert resp.issuer_data == data2
    
    # Invalid update (non-existent)
    resp_fail = registry.process_request(api.UpdateIssuerDetailsRequest("Unknown", data1))
    assert resp_fail.issuer_data is None

def test_registry_bulk_get():
    registry = RegistryInstance()
    pk = api.PublicKeyBLS(b"k")
    d1 = api.IssuerPublicData("I1", pk, "0", 1, 1)
    d2 = api.IssuerPublicData("I2", pk, "0", 1, 1)
    
    registry.process_request(api.RegisterIssuerDetailsRequest("I1", d1))
    registry.process_request(api.RegisterIssuerDetailsRequest("I2", d2))
    
    resp = registry.process_request(api.BulkGetIssuerDetailsRequest())
    assert len(resp.issuers_data) == 2
    names = [d.issuer_name for d in resp.issuers_data]
    assert "I1" in names
    assert "I2" in names
