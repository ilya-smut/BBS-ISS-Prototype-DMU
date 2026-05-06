import bbs_iss.interfaces.requests_api as api
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
import bbs_iss.utils.utils as utils

issuer = IssuerInstance()
pub_key = issuer.public_key
holder = HolderInstance()
attributes = api.IssuanceAttributes()
attributes.append("secret", utils.gen_link_secret(), api.AttributeType.HIDDEN)
attributes.append("not_secret", "very not secret", api.AttributeType.REVEALED)
attributes.append("name", "Alice", api.AttributeType.REVEALED)
attributes.append("studentId", "S-001", api.AttributeType.REVEALED)

# 1. Blind Issuance
print("--- Starting initial Blind Issuance ---")
init_request = holder.issuance_request(issuer_pub_key=pub_key, attributes=attributes, cred_name="test-cred")
freshness_response = issuer.process_request(init_request)
blind_sign_request = holder.process_request(freshness_response)

forward_vc_response = issuer.process_request(blind_sign_request)
holder.process_request(forward_vc_response)

old_vc = holder.credentials["test-cred"][0]
print(f"Old VC Exp: {old_vc.credential_subject['validUntil']}")

# 2. Re-issuance Flow
print("\n--- Starting Re-issuance Flow ---")
re_issuance_req = holder.re_issuance_request(vc_name="test-cred", always_hidden_keys=["secret"])
freshness_resp2 = issuer.process_request(re_issuance_req)
forward_vp_and_cmt_req = holder.process_request(freshness_resp2)

print("Holder generated FORWARD_VP_AND_CMT request.")

# We set the re_issuance_window_days=100 to ensure the credential passes the expiration check even if it's 7 weeks away.
issuer.set_re_issuance_window_days(100)
new_forward_vc_resp = issuer.process_request(forward_vp_and_cmt_req)

print("Issuer processed RE_ISSUANCE and issued new VC.")

# Holder processes new VC
is_valid = holder.process_request(new_forward_vc_resp)
print(f"New VC unblinded and verified: {is_valid}")

new_vc = holder.credentials["test-cred"][0]
print(f"New VC Exp: {new_vc.credential_subject['validUntil']}")
print("Re-issuance flow completed successfully!")

# 3. Negative testing: Modified commitment
print("\n--- Testing Cryptographic Binding (Negative Test) ---")
re_issuance_req_neg = holder.re_issuance_request(vc_name="test-cred", always_hidden_keys=["secret"])
freshness_resp_neg = issuer.process_request(re_issuance_req_neg)
forward_vp_and_cmt_req_neg = holder.process_request(freshness_resp_neg)

# Modify the commitment bytes to simulate an attack
original_commitment = forward_vp_and_cmt_req_neg.commitment
forward_vp_and_cmt_req_neg.commitment = b"modified_commitment1234567890123"

issuer.set_re_issuance_window_days(100)
try:
    issuer.process_request(forward_vp_and_cmt_req_neg)
    print("WARNING: Expected failure, but succeeded!")
except Exception as e:
    print(f"Cryptographic binding successfully caught mismatch. Error: {e}")
