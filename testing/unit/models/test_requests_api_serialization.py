import pytest
import json
import ursa_bbs_signatures as bbs
from bbs_iss.interfaces.requests_api import (
    Request, RequestType, VCIssuanceRequest, BlindSignRequest,
    FreshnessUpdateResponse, ForwardVCResponse, VPRequest,
    ForwardVPResponse, ForwardVpAndCmtRequest, RegisterIssuerDetailsRequest,
    UpdateIssuerDetailsRequest, GetIssuerDetailsRequest, IssuerDetailsResponse,
    BulkGetIssuerDetailsRequest, BulkIssuerDetailsResponse,
    PublicKeyBLS, KeyedIndexedMessage, IssuerPublicData
)
from bbs_iss.interfaces.credential import VerifiableCredential, VerifiablePresentation

def test_public_key_serialization():
    pk = PublicKeyBLS(b"some_bytes_123")
    d = pk.to_dict()
    pk2 = PublicKeyBLS.from_dict(d)
    assert pk == pk2
    assert d == {"key": b"some_bytes_123".hex()}

def test_keyed_indexed_message_serialization():
    m = KeyedIndexedMessage(index=5, message="hello", key="greeting")
    d = m.to_dict()
    m2 = KeyedIndexedMessage.from_dict(d)
    assert m.index == m2.index
    assert m.message == m2.message
    assert m.key == m2.key

def test_vc_issuance_request_serialization():
    req = VCIssuanceRequest()
    d = req.to_dict()
    req2 = Request.from_dict(d)
    assert isinstance(req2, VCIssuanceRequest)
    assert req2.request_type == RequestType.ISSUANCE

def test_blind_sign_request_serialization():
    attr = KeyedIndexedMessage(1, "val", "key")
    blinded = KeyedIndexedMessage(2, "", "hidden")
    req = BlindSignRequest(
        revealed_attributes=[attr],
        commitment=b"commit",
        total_messages=10,
        proof=b"proof_bytes",
        messages_with_blinded_indices=[blinded]
    )
    json_str = req.to_json()
    req2 = Request.from_json(json_str)
    
    assert isinstance(req2, BlindSignRequest)
    assert req2.commitment == b"commit"
    assert req2.proof == b"proof_bytes"
    assert len(req2.revealed_attributes) == 1
    assert req2.revealed_attributes[0].key == "key"

def test_freshness_response_serialization():
    resp = FreshnessUpdateResponse(b"nonce123")
    d = resp.to_dict()
    resp2 = Request.from_dict(d)
    assert isinstance(resp2, FreshnessUpdateResponse)
    assert resp2.nonce == b"nonce123"

def test_forward_vc_serialization():
    vc = VerifiableCredential(issuer="Iss", credential_subject={"a": "b"}, proof=b"sig")
    resp = ForwardVCResponse(vc)
    d = resp.to_dict()
    resp2 = Request.from_dict(d)
    assert isinstance(resp2, ForwardVCResponse)
    assert resp2.vc.issuer == "Iss"
    assert resp2.vc.proof == b"sig"

def test_vp_request_serialization():
    req = VPRequest(requested_attributes=["name", "age"], nonce=b"n")
    d = req.to_dict()
    req2 = Request.from_dict(d)
    assert isinstance(req2, VPRequest)
    assert req2.requested_attributes == ["name", "age"]
    assert req2.nonce == b"n"

def test_forward_vp_serialization():
    vp = VerifiablePresentation(verifiableCredential={"proof": b"zkp"})
    pk = PublicKeyBLS(b"pk")
    resp = ForwardVPResponse(vp, pk)
    d = resp.to_dict()
    resp2 = Request.from_dict(d)
    assert isinstance(resp2, ForwardVPResponse)
    assert resp2.vp.verifiableCredential["proof"] == b"zkp"
    assert resp2.pub_key.key == b"pk"

def test_forward_vp_and_cmt_serialization():
    vp = VerifiablePresentation(verifiableCredential={"proof": b"zkp"})
    attr = KeyedIndexedMessage(1, "val", "key")
    req = ForwardVpAndCmtRequest(
        vp=vp,
        commitment=b"c",
        proof=b"p",
        revealed_attributes=[attr],
        messages_with_blinded_indices=[],
        total_messages=5
    )
    d = req.to_dict()
    req2 = Request.from_dict(d)
    assert isinstance(req2, ForwardVpAndCmtRequest)
    assert req2.commitment == b"c"
    assert req2.vp.verifiableCredential["proof"] == b"zkp"

def test_registry_requests_serialization():
    pk = PublicKeyBLS(b"pk")
    data = IssuerPublicData("Iss", pk, "00", 1, 7)
    
    # Register
    req = RegisterIssuerDetailsRequest("Iss", data)
    req2 = Request.from_dict(req.to_dict())
    assert isinstance(req2, RegisterIssuerDetailsRequest)
    assert req2.issuer_data.issuer_name == "Iss"
    
    # Update
    req_up = UpdateIssuerDetailsRequest("Iss", data)
    req_up2 = Request.from_dict(req_up.to_dict())
    assert isinstance(req_up2, UpdateIssuerDetailsRequest)
    
    # Get
    req_get = GetIssuerDetailsRequest("Iss")
    req_get2 = Request.from_dict(req_get.to_dict())
    assert isinstance(req_get2, GetIssuerDetailsRequest)
    assert req_get2.issuer_name == "Iss"
    
    # Response
    resp = IssuerDetailsResponse(data)
    resp2 = Request.from_dict(resp.to_dict())
    assert isinstance(resp2, IssuerDetailsResponse)
    assert resp2.issuer_data.issuer_name == "Iss"
    
    # Bulk Request
    req_bulk = BulkGetIssuerDetailsRequest()
    req_bulk2 = Request.from_dict(req_bulk.to_dict())
    assert isinstance(req_bulk2, BulkGetIssuerDetailsRequest)
    
    # Bulk Response
    resp_bulk = BulkIssuerDetailsResponse([data, data])
    resp_bulk2 = Request.from_dict(resp_bulk.to_dict())
    assert isinstance(resp_bulk2, BulkIssuerDetailsResponse)
    assert len(resp_bulk2.issuers_data) == 2

def test_pretty_print_smoke():
    # Just ensure they don't crash
    pk = PublicKeyBLS(b"pk"*16)
    data = IssuerPublicData("Iss", pk, "00", 1, 7)
    vc = VerifiableCredential(issuer="Iss", credential_subject={"a": "b"}, proof=b"sig")
    vp = VerifiablePresentation(verifiableCredential={"proof": b"zkp", "credentialSubject": {"a": "b"}})
    
    requests = [
        VCIssuanceRequest(),
        BlindSignRequest(revealed_attributes=[], commitment=b"c", total_messages=1, proof=b"p", messages_with_blinded_indices=[]),
        FreshnessUpdateResponse(b"n"),
        ForwardVCResponse(vc),
        VPRequest(["a"], b"n"),
        ForwardVPResponse(vp, pk),
        RegisterIssuerDetailsRequest("Iss", data),
        IssuerDetailsResponse(None),
        BulkIssuerDetailsResponse([data])
    ]
    
    for r in requests:
        s = r.get_print_string()
        assert isinstance(s, str)
        assert len(s) > 0
