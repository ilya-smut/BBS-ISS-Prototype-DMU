from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
import bbs_iss.utils.utils as utils
import bbs_iss.interfaces.requests_api as api
import json

# Helper for visual separation
def print_section(title: str):
    print("\n" + "="*80)
    print(f"{title:^80}")
    print("="*80 + "\n")

def print_step(step: str):
    print(f"\n>>> {step}")
    print("-" * 40)

# 0. Initialize Entities
print_section("SYSTEM INITIALIZATION")
registry = RegistryInstance()
issuer = IssuerInstance()
issuer.set_issuer_parameters({"issuer": "VeryCredible-University"})
issuer.set_epoch_size_days(49)
issuer.set_re_issuance_window_days(7)

holder = HolderInstance()
verifier = VerifierInstance()
print("Entities initialized: Registry, Issuer, Holder, Verifier.")

# 1. Registry Setup
print_section("PHASE 1: REGISTRY SETUP")

print_step("Registering Issuer with Registry")
reg_req = issuer.register_issuer()
print("Request (Issuer -> Registry):\n" + reg_req.get_print_string())
reg_resp = registry.process_request(reg_req)
print("Response (Registry -> Issuer):\n" + reg_resp.get_print_string())
issuer.process_request(reg_resp)

print_step("Syncing Verifier with Registry")
bulk_req_v = verifier.fetch_all_issuer_details()
bulk_resp_v = registry.process_request(bulk_req_v)
verifier.process_request(bulk_resp_v)
print("Verifier local cache updated.")

print_step("Syncing Holder with Registry")
bulk_req_h = holder.fetch_all_issuer_details()
bulk_resp_h = registry.process_request(bulk_req_h)
holder.process_request(bulk_resp_h)
print("Holder local cache updated.")

# 2. Initial Configuration Status
print_section("CURRENT SYSTEM STATUS")
print("Issuer Configuration:", issuer.get_configuration())
print("Registry Status:", registry.get_status_string())

# 3. Credential Issuance
print_section("PHASE 2: CREDENTIAL ISSUANCE (BBS+ BLIND SIGNING)")

attributes = api.IssuanceAttributes()
attributes.append("name", "Ilya", api.AttributeType.REVEALED)
attributes.append("id", "123456", api.AttributeType.REVEALED)
attributes.append("age", "23", api.AttributeType.REVEALED)
attributes.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)

print_step("Step 1: Holder sends Issuance Request & Issuer returns Freshness Nonce")
iss_req = holder.issuance_request("VeryCredible-University", attributes, "student-card")
print("Request (Holder -> Issuer):\n" + iss_req.get_print_string())
freshness = issuer.process_request(iss_req)
print("Response (Issuer -> Holder):\n" + freshness.get_print_string())

print_step("Step 2: Holder generates Blind Commitment & Proof of Knowledge")
blind_req = holder.process_request(freshness)
print("Request (Holder -> Issuer):\n" + blind_req.get_print_string())

print_step("Step 3: Issuer Blindly Signs attributes and returns Verifiable Credential")
forward_vc = issuer.process_request(blind_req)
print("Response (Issuer -> Holder):\n" + forward_vc.get_print_string())
holder.process_request(forward_vc)

print("\n[SUCCESS] Holder has received and stored the credential.")

# 4. Zero-Knowledge Proof Presentation
print_section("PHASE 3: ZERO-KNOWLEDGE PROOF PRESENTATION")

print_step("Step 1: Verifier sends Presentation Request (Challenge)")
presentation_req = verifier.presentation_request(["name", "id", "validUntil"])
print("Request (Verifier -> Holder):\n" + presentation_req.get_print_string())

print_step("Step 2: Holder generates ZKP (selective disclosure + hidden LinkSecret)")
presentation_resp = holder.present_credential(presentation_req, "student-card", always_hidden_keys=["age", "LinkSecret"])
print("Response (Holder -> Verifier):\n" + presentation_resp.get_print_string())

print_step("Step 3: Verifier validates the Proof and checks Revocation Status")
valid, disclosed_messages, vp = verifier.process_request(presentation_resp)

print("\n--- VERIFICATION RESULT ---")
print(f"Cryptographic Proof Valid: {valid}")
print(f"Disclosed Attributes:      {disclosed_messages}")
print("---------------------------\n")

# 5. Credential Re-issuance (Freshness Update)
print_section("PHASE 4: CREDENTIAL RE-ISSUANCE (FRESHNESS UPDATE)")

print(">>> Adjusting Issuer Window to trigger re-issuance eligibility...")
issuer.set_re_issuance_window_days(52)
print(issuer.get_configuration())

print_step("Step 1: Holder requests Freshness Update for re-issuance")
reiss_req = holder.re_issuance_request("student-card", always_hidden_keys=["LinkSecret"])
print("Request (Holder -> Issuer):\n" + reiss_req.get_print_string())
freshness_reiss = issuer.process_request(reiss_req)
print("Response (Issuer -> Holder):\n" + freshness_reiss.get_print_string())

print_step("Step 2: Holder proves ownership of old VC & provides new Commitment")
blind_req_reiss = holder.process_request(freshness_reiss)
print("Request (Holder -> Issuer):\n" + blind_req_reiss.get_print_string())

print_step("Step 3: Issuer verifies proof and issues Updated VC")
forward_vc_reiss = issuer.process_request(blind_req_reiss)
print("Response (Issuer -> Holder):\n" + forward_vc_reiss.get_print_string())
holder.process_request(forward_vc_reiss)

print("\n[SUCCESS] Credential successfully re-issued with updated validity.")
print_section("FINAL HOLDER STATE")
import json
print(json.dumps(holder.credentials["student-card"][0].credential_subject, indent=4))
print("\n" + "="*80)
print(f"{'DEMO COMPLETED SUCCESSFULLY':^80}")
print("="*80 + "\n")