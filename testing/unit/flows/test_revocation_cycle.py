import pytest
from freezegun import freeze_time
from datetime import datetime, timedelta, timezone
import bbs_iss.interfaces.requests_api as api
from bbs_iss.entities.issuer import IssuerInstance, BitstringManager
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.utils.utils import gen_link_secret
from bbs_iss.exceptions.exceptions import BitstringExhaustedError

def test_full_revocation_and_reissuance_cycle():
    """
    Rigorously tests the full lifecycle of revocation and re-issuance:
    1. Setup and Registration
    2. Bulk Issuance
    3. Bulk Revocation & Sync
    4. Verification of Revocation Status
    5. Re-issuance of Revoked Credentials
    6. Final Verification of Validity
    """
    # 1) Initialise an issuer, registry, and holder
    registry = RegistryInstance()
    issuer = IssuerInstance()
    issuer.set_issuer_parameters({"issuer": "Test-Issuer"})
    
    # Configure re-issuance window to be very large to ensure immediate eligibility
    # Epoch = 7 days, Window = 100 days
    issuer.set_epoch_size_days(7)
    issuer.set_re_issuance_window_days(100)
    
    holder = HolderInstance()
    issuer_name = "Test-Issuer"
    
    # 2) Issuer registers with registry
    reg_req = issuer.register_issuer()
    reg_resp = registry.process_request(reg_req)
    issuer.process_request(reg_resp)
    
    # Holder initial sync to get issuer public data
    sync_req = holder.fetch_all_issuer_details()
    sync_resp = registry.process_request(sync_req)
    holder.process_request(sync_resp)
    
    # 3) Holder obtains a large amount of credentials
    num_creds = 20
    cred_names = [f"cred-{i}" for i in range(num_creds)]
    link_secret = gen_link_secret()
    
    for name in cred_names:
        attrs = api.IssuanceAttributes()
        attrs.append("name", "Alice", api.AttributeType.REVEALED)
        attrs.append("LinkSecret", link_secret, api.AttributeType.HIDDEN)
        
        # Standard 4-step issuance flow
        init = holder.issuance_request(issuer_name, attrs, name)
        freshness = issuer.process_request(init)
        blind = holder.process_request(freshness)
        vc_resp = issuer.process_request(blind)
        holder.process_request(vc_resp)
        
    # 4) Issuer then revokes a big chunk of them
    # We revoke the first half (10 credentials)
    for i in range(10):
        name = cred_names[i]
        vc, _ = holder.credentials[name]
        revocation_idx_hex = vc.credential_subject["revocationMaterial"]
        issuer.revoke_index(revocation_idx_hex)
        
    # 5) Issuer updates registry with the new bitstring
    update_req = issuer.update_issuer_details()
    update_resp = registry.process_request(update_req)
    issuer.process_request(update_resp)
    
    # 6) Holder queries issuer info from registry obtaining a new bitstring
    sync_req = holder.fetch_all_issuer_details()
    sync_resp = registry.process_request(sync_req)
    holder.process_request(sync_resp)
    
    # 7) Checks every single credential in storage to see if it was revoked or not
    for i in range(num_creds):
        name = cred_names[i]
        vc, _ = holder.credentials[name]
        idx_hex = vc.credential_subject["revocationMaterial"]
        is_revoked = holder.public_data_cache.check_bit_index(issuer_name, idx_hex)
        
        if i < 10:
            assert is_revoked is True, f"Credential {name} (index {idx_hex}) should be revoked"
        else:
            assert is_revoked is False, f"Credential {name} (index {idx_hex}) should be valid"
            
    # 8) Sends requests to issuer to re-issue revoked credentials
    for i in range(10):
        name = cred_names[i]
        
        # Standard 3-step re-issuance flow
        re_init = holder.re_issuance_request(name, always_hidden_keys=["LinkSecret"])
        freshness = issuer.process_request(re_init)
        re_req = holder.process_request(freshness)
        new_vc_resp = issuer.process_request(re_req)
        holder.process_request(new_vc_resp)
        
    # 9) Issuer updates registry again (to reflect updated bitstring after re-issuance)
    # Note: re-issuance revokes the old bit and assigns a new one.
    update_req = issuer.update_issuer_details()
    update_resp = registry.process_request(update_req)
    issuer.process_request(update_resp)
    
    # 10) Holder obtains new bitstring and verifies that all creds are valid
    sync_req = holder.fetch_all_issuer_details()
    sync_resp = registry.process_request(sync_req)
    holder.process_request(sync_resp)
    
    for name in cred_names:
        vc, _ = holder.credentials[name]
        idx_hex = vc.credential_subject["revocationMaterial"]
        is_revoked = holder.public_data_cache.check_bit_index(issuer_name, idx_hex)
        assert is_revoked is False, f"Credential {name} (index {idx_hex}) should be valid after re-issuance"

@freeze_time("2026-01-01")
def test_bitstring_exhaustion_and_reuse():
    """
    Tests that the bitstring correctly exhausts when full and
    reclaims capacity once credentials expire in a new epoch.
    """
    # 1) init issuer, holder, registry
    registry = RegistryInstance()
    issuer = IssuerInstance()
    # Tiny bitstring for testing exhaustion: 8 bits
    issuer.bitstring_manager = BitstringManager(default_num_bytes=1)
    
    issuer.set_issuer_parameters({"issuer": "Exhaustion-Issuer"})
    # Epoch = 7 days, Window = 0 (to make expiry exactly 1 epoch away)
    issuer.set_epoch_size_days(7)
    issuer.set_re_issuance_window_days(0)
    
    holder = HolderInstance()
    issuer_name = "Exhaustion-Issuer"
    
    # 2) register issuer, holder obtains key
    reg_req = issuer.register_issuer()
    reg_resp = registry.process_request(reg_req)
    issuer.process_request(reg_resp)
    sync_req = holder.fetch_all_issuer_details()
    holder.process_request(registry.process_request(sync_req))

    # 3) holder requests the full available amount of credentials (8 bits)
    link_secret = gen_link_secret()
    for i in range(8):
        attrs = api.IssuanceAttributes()
        attrs.append("name", f"User-{i}", api.AttributeType.REVEALED)
        attrs.append("LinkSecret", link_secret, api.AttributeType.HIDDEN)
        
        init = holder.issuance_request(issuer_name, attrs, f"cred-{i}")
        freshness = issuer.process_request(init)
        blind = holder.process_request(freshness)
        vc_resp = issuer.process_request(blind)
        holder.process_request(vc_resp)
        
    # 4) Try to request one more (verify that exception is thrown)
    attrs = api.IssuanceAttributes()
    attrs.append("name", "One-Too-Many", api.AttributeType.REVEALED)
    attrs.append("LinkSecret", link_secret, api.AttributeType.HIDDEN)
    
    # We can start the interaction
    init = holder.issuance_request(issuer_name, attrs, "fail-cred")
    freshness = issuer.process_request(init)
    blind = holder.process_request(freshness)
    
    # But signing should fail due to exhaustion
    with pytest.raises(BitstringExhaustedError):
        issuer.process_request(blind)
    
    # Manually reset holder state because the issuer failed but the holder is still waiting
    holder.state.end_interaction()
        
    # 5) use mock time to move the epoch (move forward by 8 days)
    # Original 'now' was Jan 1. Next epoch starts Jan 8.
    with freeze_time("2026-01-09"):
        # 6) verify that holder can request more credentials (bits will be released)
        # The credentials issued on Jan 1 had an expiry_epoch of 1.
        # Now current_epoch is 1, so BitstringManager will see them as available.
        
        # We need fresh attributes for the retry, otherwise they contain duplicate meta fields from the failed attempt
        attrs_retry = api.IssuanceAttributes()
        attrs_retry.append("name", "Now-It-Works", api.AttributeType.REVEALED)
        attrs_retry.append("LinkSecret", link_secret, api.AttributeType.HIDDEN)
        
        init = holder.issuance_request(issuer_name, attrs_retry, "success-cred")
        freshness = issuer.process_request(init)
        blind = holder.process_request(freshness)
        # This should now succeed!
        vc_resp = issuer.process_request(blind)
        assert holder.process_request(vc_resp) is True
