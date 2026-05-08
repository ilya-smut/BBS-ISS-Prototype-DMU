import pytest
import os
import copy
from datetime import datetime, timedelta, timezone
import ursa_bbs_signatures as bbs

from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.interfaces.credential import VerifiableCredential
import bbs_iss.interfaces.requests_api as api
from bbs_iss.utils.utils import gen_link_secret
from bbs_iss.exceptions.exceptions import ProofValidityError

@pytest.fixture
def issued_credential_and_entities():
    issuer = IssuerInstance()
    # Configure a realistic re-issuance window
    issuer.set_re_issuance_window_days(7)
    issuer.set_epoch_size_days(7) # Short valid period for tests
    
    holder = HolderInstance()
    
    attributes = api.IssuanceAttributes()
    attributes.append("name", "Alice", api.AttributeType.REVEALED)
    attributes.append("uni", "DMU", api.AttributeType.REVEALED)
    link_secret = gen_link_secret()
    attributes.append("LinkSecret", link_secret, api.AttributeType.HIDDEN)
    
    cred_name = "test-cred"
    
    # Issuance flow
    issuer_name = "Mock-Issuer"
    data = api.IssuerPublicData(issuer_name, issuer.public_key, issuer.bitstring_manager.get_revocation_bitstring_hex(), 52, 7)
    holder.public_data_cache.update(issuer_name, data)
    
    init_req = holder.issuance_request(
        issuer_name=issuer_name,
        attributes=attributes,
        cred_name=cred_name
    )
    freshness = issuer.process_request(init_req)
    blind_req = holder.process_request(freshness)
    forward_vc = issuer.process_request(blind_req)
    holder.process_request(forward_vc)
    
    return holder, issuer, cred_name, link_secret


class TestReissuanceFlow:

    def test_stress_reissuance(self, issued_credential_and_entities):
        """Stress test: 100 sequential reissuance requests"""
        holder, issuer, cred_name, _ = issued_credential_and_entities
        
        # Configure the issuer for stress testing so the credential never expires during the test
        # We set a large re-issuance window and small validity
        issuer.set_re_issuance_window_days(1000)
        issuer.set_epoch_size_days(7)

        for _ in range(100):
            init_req = holder.re_issuance_request(
                vc_name=cred_name,
                always_hidden_keys=["LinkSecret"]
            )
            freshness_resp = issuer.process_request(init_req)
            re_issuance_req = holder.process_request(freshness_resp)
            
            new_vc_resp = issuer.process_request(re_issuance_req)
            assert holder.process_request(new_vc_resp) is True
            
    def test_concurrent_separation(self):
        """Ensure state isolation across multiple concurrent interactions."""
        issuer = IssuerInstance()
        issuer.set_re_issuance_window_days(100) # Ensure it doesn't fail expiration check
        issuer.set_epoch_size_days(7)
        
        holders = []
        cred_names = []
        for i in range(3):
            holder = HolderInstance()
            attrs = api.IssuanceAttributes()
            attrs.append("name", f"User{i}", api.AttributeType.REVEALED)
            attrs.append("LinkSecret", gen_link_secret(), api.AttributeType.HIDDEN)
            cred_name = f"cred{i}"
            
            issuer_name = "Mock-Issuer"
            data = api.IssuerPublicData(issuer_name, issuer.public_key, issuer.bitstring_manager.get_revocation_bitstring_hex(), 52, 7)
            holder.public_data_cache.update(issuer_name, data)
            init = holder.issuance_request(issuer_name, attrs, cred_name)
            freshness = issuer.process_request(init)
            blind_req = holder.process_request(freshness)
            forward_vc = issuer.process_request(blind_req)
            holder.process_request(forward_vc)
            
            holders.append(holder)
            cred_names.append(cred_name)

        # Now all 3 holders attempt to re-issue at once
        init_req_0 = holders[0].re_issuance_request(
            vc_name=cred_names[0],
            always_hidden_keys=["LinkSecret"]
        )
        freshness_0 = issuer.process_request(init_req_0)
        
        # If holder 1 tries to start a request while holder 0 is interacting, it should raise Exception (IssuerNotAvailable)
        init_req_1 = holders[1].re_issuance_request(
            vc_name=cred_names[1],
            always_hidden_keys=["LinkSecret"]
        )
        with pytest.raises(Exception):
            issuer.process_request(init_req_1)
            
        re_req_0 = holders[0].process_request(freshness_0)
        new_vc_0 = issuer.process_request(re_req_0)
        assert holders[0].process_request(new_vc_0) is True

        # Now holder 1 can interact
        freshness_1 = issuer.process_request(init_req_1)
        re_req_1 = holders[1].process_request(freshness_1)
        new_vc_1 = issuer.process_request(re_req_1)
        assert holders[1].process_request(new_vc_1) is True


    def test_replay_different_nonce(self, issued_credential_and_entities):
        """Attempting to use a valid VP but signed against a wrong or stale issuer nonce."""
        holder, issuer, cred_name, _ = issued_credential_and_entities
        
        # Proper interaction starts
        init_req = holder.re_issuance_request(
            vc_name=cred_name,
            always_hidden_keys=["LinkSecret"]
        )
        freshness_resp = issuer.process_request(init_req)
        
        # Attacker builds request with a different nonce
        wrong_nonce = os.urandom(32)
        wrong_freshness_resp = api.FreshnessUpdateResponse(nonce=wrong_nonce)
        
        # Holder processes the wrong freshness
        re_issuance_req = holder.process_request(wrong_freshness_resp)
        
        # The issuer checks against freshness_resp.nonce
        with pytest.raises(ProofValidityError):
            issuer.process_request(re_issuance_req)


    def test_replay_different_commitment(self, issued_credential_and_entities):
        """
        Attempting to substitute the commitment to steal the re-issued credential.
        Ensure that for fake commitment the real nonce is used, exact attribute keys, 
        and same public key, but an arbitrary value is changed (like LinkSecret).
        """
        holder, issuer, cred_name, _ = issued_credential_and_entities
        
        # 1. Start interaction
        init_req = holder.re_issuance_request(
            vc_name=cred_name,
            always_hidden_keys=["LinkSecret"]
        )
        freshness_resp = issuer.process_request(init_req)
        real_nonce = freshness_resp.nonce
        
        # 2. Honest holder generates a valid request
        valid_re_issuance_req = holder.process_request(freshness_resp)
        
        # 3. Attacker intercepts valid VP and tries to substitute with their own fake commitment
        attacker_holder = HolderInstance()
        attacker_attrs = api.IssuanceAttributes()
        attacker_attrs.append("name", "Alice", api.AttributeType.REVEALED) # Same attributes
        attacker_attrs.append("uni", "DMU", api.AttributeType.REVEALED)
        
        # BUT with a different LinkSecret (the attacker's secret)
        fake_link_secret = gen_link_secret()
        attacker_attrs.append("LinkSecret", fake_link_secret, api.AttributeType.HIDDEN)
        
        # The attacker builds a valid commitment and proof of commitment for the fake_link_secret using the real nonce
        attacker_attrs.build_commitment_append_meta(real_nonce, issuer.public_key)
        
        malicious_req = api.ForwardVpAndCmtRequest(
            vp=valid_re_issuance_req.vp,
            attributes=attacker_attrs
        )
        
        # 4. Send malicious request to issuer
        with pytest.raises(ProofValidityError):
            issuer.process_request(malicious_req)

    def test_attribute_modification(self, issued_credential_and_entities):
        """Changing any value of any meta and attribute field in credential should result in failure."""
        holder, issuer, cred_name, _ = issued_credential_and_entities
        
        init_req = holder.re_issuance_request(
            vc_name=cred_name,
            always_hidden_keys=["LinkSecret"]
        )
        freshness_resp = issuer.process_request(init_req)
        
        re_issuance_req = holder.process_request(freshness_resp)
        
        # Attacker modifies a revealed attribute in the request
        for attr in re_issuance_req.revealed_attributes:
            if attr.key == "name":
                attr.message = "Eve"
        
        with pytest.raises(ValueError, match="Attribute value mismatch for key name"):
            issuer.process_request(re_issuance_req)


    def test_reissuance_window_boundary(self, issued_credential_and_entities):
        """Credential not in re-issuance period should not be re-issued."""
        holder, issuer, cred_name, _ = issued_credential_and_entities
        
        original_vc, _ = holder.credentials[cred_name]
        
        # With epoch-based validity, the expiry is at the next epoch boundary.
        # If we set the window to a negative value, any valid credential will fail the check.
        issuer.set_re_issuance_window_days(-1)
        
        init_req = holder.re_issuance_request(
            vc_name=cred_name,
            always_hidden_keys=["LinkSecret"]
        )
        freshness_resp = issuer.process_request(init_req)
        re_issuance_req = holder.process_request(freshness_resp)
        
        # Will fail because expiration is ~7 days away, which is > -1
        with pytest.raises(Exception):
            issuer.process_request(re_issuance_req)


    def test_reissuance_state_reset_on_failure(self, issued_credential_and_entities):
        """Verifying issuer resets after a failure."""
        holder, issuer, cred_name, _ = issued_credential_and_entities
        
        init_req = holder.re_issuance_request(
            vc_name=cred_name,
            always_hidden_keys=["LinkSecret"]
        )
        freshness_resp = issuer.process_request(init_req)
        re_issuance_req = holder.process_request(freshness_resp)
        
        # Introduce a failure by passing wrong proof in the VP
        re_issuance_req.vp.verifiableCredential["proof"] = b'badproof'
        
        with pytest.raises(Exception):
            issuer.process_request(re_issuance_req)
            
        # State should be reset, meaning we can start a new interaction immediately
        assert issuer.state.available is True
        
        # Make a valid fresh request to test that it works
        req_freshness = api.Request(api.RequestType.RE_ISSUANCE)
        assert issuer.process_request(req_freshness) is not None


    def test_reissuance_missing_validity(self, issued_credential_and_entities):
        """Rejecting credentials without an expiry field."""
        holder, issuer, cred_name, _ = issued_credential_and_entities
        
        init_req = holder.re_issuance_request(
            vc_name=cred_name,
            always_hidden_keys=["LinkSecret"]
        )
        freshness_resp = issuer.process_request(init_req)
        re_issuance_req = holder.process_request(freshness_resp)
        
        # Attacker deliberately drops the validUntil from the VP to bypass expiration checks
        del re_issuance_req.vp.verifiableCredential["credentialSubject"]["validUntil"]
        
        with pytest.raises(Exception):
            issuer.process_request(re_issuance_req)


    def test_reissued_credential_integrity(self, issued_credential_and_entities):
        """Checking the new attributes (expiry, metaHash) of the re-issued VC."""
        holder, issuer, cred_name, _ = issued_credential_and_entities
        
        original_vc, _ = holder.credentials[cred_name]
        old_expiry = original_vc.credential_subject["validUntil"]
        old_metaHash = original_vc.credential_subject["metaHash"]
        
        # Set a big window so it passes
        issuer.set_re_issuance_window_days(100)
        
        init_req = holder.re_issuance_request(
            vc_name=cred_name,
            always_hidden_keys=["LinkSecret"]
        )
        freshness_resp = issuer.process_request(init_req)
        re_issuance_req = holder.process_request(freshness_resp)
        
        new_vc_resp = issuer.process_request(re_issuance_req)
        holder.process_request(new_vc_resp)
        
        new_vc, _ = holder.credentials[cred_name]
        
        new_expiry = new_vc.credential_subject["validUntil"]
        new_metaHash = new_vc.credential_subject["metaHash"]
        
        # In epoch-based logic, instantaneous re-issuance yields the exact same epoch boundary.
        assert new_expiry == old_expiry
        assert new_metaHash == old_metaHash
        
        from bbs_iss.entities.verifier import VerifierInstance
        verifier = VerifierInstance()
        
        # Sync verifier
        registry = RegistryInstance()
        reg_req = issuer.register_issuer()
        reg_resp = registry.process_request(reg_req)
        issuer.process_request(reg_resp)
        
        bulk_req = verifier.fetch_all_issuer_details()
        bulk_resp = registry.process_request(bulk_req)
        verifier.process_request(bulk_resp)

        vp_req = verifier.presentation_request(requested_attributes=["name"])
        vp_resp = holder.present_credential(vp_req, cred_name, always_hidden_keys=["LinkSecret"])
        
        valid, revealed, _ = verifier.process_request(vp_resp)
        assert valid is True
        assert revealed == {"name": "Alice"}
