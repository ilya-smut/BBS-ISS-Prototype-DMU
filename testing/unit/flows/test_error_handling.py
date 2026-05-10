import pytest
import ursa_bbs_signatures as bbs
import bbs_iss.interfaces.requests_api as api
from bbs_iss.entities.issuer import IssuerInstance, BitstringManager
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.utils.utils import gen_link_secret
from freezegun import freeze_time

def test_issuer_unavailable_error():
    """Test that ERROR response is returned when issuer is busy."""
    issuer = IssuerInstance()
    issuer.set_issuer_parameters({"issuer": "Busy-Issuer"})
    
    # 1. Start an interaction to make issuer busy
    issuance_req = api.VCIssuanceRequest()
    issuer.process_request(issuance_req)
    assert issuer.state.available is False
    
    # 2. Try to start another interaction
    second_req = api.VCIssuanceRequest()
    error_resp = issuer.process_request(second_req)
    
    assert isinstance(error_resp, api.ErrorResponse)
    assert error_resp.error_type == api.ErrorType.ISSUER_UNAVAILABLE
    assert error_resp.original_request_type == api.RequestType.ISSUANCE

def test_bitstring_exhaustion_error():
    """Test that ERROR response is returned when bitstring is exhausted."""
    issuer = IssuerInstance()
    issuer.bitstring_manager = BitstringManager(default_num_bytes=1) # 8 bits
    issuer.set_issuer_parameters({"issuer": "Full-Issuer"})
    
    holder = HolderInstance()
    link_secret = gen_link_secret()
    
    # 1. Fill up the bitstring
    for i in range(8):
        attrs = api.IssuanceAttributes()
        attrs.append("name", f"User-{i}", api.AttributeType.REVEALED)
        attrs.append("LinkSecret", link_secret, api.AttributeType.HIDDEN)
        
        init = api.VCIssuanceRequest()
        freshness = issuer.process_request(init)
        attrs.build_commitment_append_meta(freshness.nonce, issuer.public_key)
        blind = api.BlindSignRequest(attrs)
        issuer.process_request(blind)
        
    # 2. Try to issue one more
    attrs = api.IssuanceAttributes()
    attrs.append("name", "Extra", api.AttributeType.REVEALED)
    attrs.append("LinkSecret", link_secret, api.AttributeType.HIDDEN)
    
    init = api.VCIssuanceRequest()
    freshness = issuer.process_request(init)
    attrs.build_commitment_append_meta(freshness.nonce, issuer.public_key)
    blind = api.BlindSignRequest(attrs)
    
    error_resp = issuer.process_request(blind)
    
    assert isinstance(error_resp, api.ErrorResponse)
    assert error_resp.error_type == api.ErrorType.BITSTRING_EXHAUSTED
    assert error_resp.original_request_type == api.RequestType.BLIND_SIGN
    # Verify issuer state is reset
    assert issuer.state.available is True

def test_verification_failed_error():
    """Test that ERROR response is returned when PoK verification fails."""
    issuer = IssuerInstance()
    issuer.set_issuer_parameters({"issuer": "Verif-Issuer"})
    
    # 1. Start interaction
    init = api.VCIssuanceRequest()
    freshness = issuer.process_request(init)
    
    # 2. Create a malformed BlindSignRequest (e.g. wrong proof)
    attrs = api.IssuanceAttributes()
    attrs.append("name", "Alice", api.AttributeType.REVEALED)
    attrs.append("secret", "hidden", api.AttributeType.HIDDEN)
    attrs.build_commitment_append_meta(freshness.nonce, issuer.public_key)
    
    blind_req = api.BlindSignRequest(attrs)
    blind_req.proof = b"invalid proof" # Tamper with proof
    
    error_resp = issuer.process_request(blind_req)
    
    assert isinstance(error_resp, api.ErrorResponse)
    assert error_resp.error_type == api.ErrorType.VERIFICATION_FAILED
    assert error_resp.original_request_type == api.RequestType.BLIND_SIGN
    # Verify issuer state is reset
    assert issuer.state.available is True

def test_invalid_state_error():
    """Test that ERROR response is returned when request arrives in wrong state."""
    issuer = IssuerInstance()
    
    # Send BLIND_SIGN without starting ISSUANCE
    blind_req = api.BlindSignRequest(revealed_attributes=[], commitment=b"cmt", total_messages=1, proof=b"proof", messages_with_blinded_indices=[])
    
    error_resp = issuer.process_request(blind_req)
    
    assert isinstance(error_resp, api.ErrorResponse)
    assert error_resp.error_type == api.ErrorType.INVALID_STATE
    assert error_resp.original_request_type == api.RequestType.BLIND_SIGN

@freeze_time("2026-01-01")
def test_reissuance_window_error():
    """Test that ERROR response is returned when re-issuance is requested outside the window."""
    issuer = IssuerInstance()
    issuer.set_issuer_parameters({"issuer": "Window-Issuer"})
    issuer.set_epoch_size_days(30)
    issuer.set_re_issuance_window_days(7) # 7 days window
    
    holder = HolderInstance()
    
    # 1. Issue a VC
    attrs = api.IssuanceAttributes()
    attrs.append("name", "Alice", api.AttributeType.REVEALED)
    attrs.append("secret", "hidden", api.AttributeType.HIDDEN)
    
    # Holder needs the issuer in cache, we bypass registry for this test
    holder.public_data_cache.update("Window-Issuer", api.IssuerPublicData("Window-Issuer", issuer.public_key, "00", 4, 30))
    
    init = holder.issuance_request("Window-Issuer", attrs, "my-vc")
    freshness = issuer.process_request(init)
    blind = holder.process_request(freshness)
    vc_resp = issuer.process_request(blind)
    holder.process_request(vc_resp)
    
    # VC was issued on Jan 1. Expiry is Feb 1 (approx).
    # Re-issuance window is 7 days before expiry.
    # Current time is Jan 1. We are NOT in the window.
    
    re_init = holder.re_issuance_request("my-vc", always_hidden_keys=["secret"])
    freshness = issuer.process_request(re_init)
    re_req = holder.process_request(freshness)
    
    error_resp = issuer.process_request(re_req)
    
    assert isinstance(error_resp, api.ErrorResponse)
    assert error_resp.error_type == api.ErrorType.INVALID_REQUEST
    assert "re-issuance window" in error_resp.message.lower()
    
def test_holder_handles_error():
    """Test that Holder correctly resets state when receiving an ERROR response."""
    issuer = IssuerInstance()
    holder = HolderInstance()
    
    # Setup cache
    holder.public_data_cache.update("Issuer", api.IssuerPublicData("Issuer", issuer.public_key, "00", 4, 30))
    
    # 1. Start interaction
    attrs = api.IssuanceAttributes()
    attrs.append("name", "Alice", api.AttributeType.REVEALED)
    init = holder.issuance_request("Issuer", attrs, "vc")
    
    # 2. Simulate error from issuer (e.g. busy)
    error_resp = api.ErrorResponse(api.RequestType.ISSUANCE, api.ErrorType.ISSUER_UNAVAILABLE)
    
    # 3. Holder processes error
    result = holder.process_request(error_resp)
    
    assert isinstance(result, api.ErrorResponse)
    assert holder.state.awaiting is False
    assert holder.state.original_request is None
