import pytest
from freezegun import freeze_time
from datetime import datetime, timedelta, timezone
import bbs_iss.interfaces.requests_api as api
from bbs_iss.entities.issuer import IssuerInstance, BitstringManager
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.utils.utils import gen_link_secret

@freeze_time("2026-01-01")
def test_reissuance_fails_on_bitstring_exhaustion():
    """
    Tests that re-issuance fails if the bitstring is full, because
    re-issuance requires assigning a NEW bit before revoking the old one.
    """
    registry = RegistryInstance()
    issuer = IssuerInstance()
    
    # Tiny bitstring: 2 bits
    issuer.bitstring_manager = BitstringManager(default_num_bytes=1)
    issuer.bitstring_manager.length = 2 
    
    issuer.set_issuer_parameters({"issuer": "Limited-Issuer"})
    issuer.set_epoch_size_days(7)
    issuer.set_re_issuance_window_days(100) # Always in window
    
    issuer_name = "Limited-Issuer"
    
    # Sync Registry (Must process response to clear Issuer state)
    reg_req = issuer.register_issuer()
    reg_resp = registry.process_request(reg_req)
    issuer.process_request(reg_resp)
    
    # Setup Holders
    holder1 = HolderInstance()
    holder2 = HolderInstance()
    
    # Sync Holders
    for h in [holder1, holder2]:
        sync_req = h.fetch_all_issuer_details()
        sync_resp = registry.process_request(sync_req)
        h.process_request(sync_resp)
    
    # 1) Exhaust the bitstring (2/2 bits used)
    link_secret = gen_link_secret()
    for h, name in [(holder1, "cred1"), (holder2, "cred2")]:
        attrs = api.IssuanceAttributes()
        attrs.append("name", "User", api.AttributeType.REVEALED)
        attrs.append("secret", link_secret, api.AttributeType.HIDDEN)
        
        init = h.issuance_request(issuer_name, attrs, name)
        freshness = issuer.process_request(init)
        blind = h.process_request(freshness)
        vc_resp = issuer.process_request(blind)
        h.process_request(vc_resp)
        
    # 2) Holder 1 tries to RE-ISSUE their credential
    re_init = holder1.re_issuance_request("cred1", always_hidden_keys=["secret"])
    re_freshness = issuer.process_request(re_init)
    re_req = holder1.process_request(re_freshness)
    
    # 3) Issuer tries to process re-issuance
    # This should fail with BITSTRING_EXHAUSTED because it needs a 3rd bit
    # (even though it's going to revoke bit #0 immediately after)
    error_resp = issuer.process_request(re_req)
    
    assert isinstance(error_resp, api.ErrorResponse)
    assert error_resp.error_type == api.ErrorType.BITSTRING_EXHAUSTED
    assert "No available indices" in error_resp.message
    
    # 4) Verify state reset
    holder1.process_request(error_resp)
    assert holder1.state.awaiting is False
    assert issuer.available is True
