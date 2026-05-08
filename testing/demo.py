from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
import bbs_iss.utils.utils as utils
import bbs_iss.interfaces.requests_api as api

# 0. Initialize Registry
registry = RegistryInstance()

# 1. Initialize Issuer
issuer = IssuerInstance()
issuer.set_issuer_parameters({
    "issuer": "VeryCredible-University"
})
issuer.set_epoch_size_days(49)
issuer.set_re_issuance_window_days(7)

# 2. Initialize Holder
holder = HolderInstance()

# 3. Initialize Verifier
verifier = VerifierInstance()

# === REGISTRY FUNCTIONS ===

# 5. Issue registrar details
print("=== Registering issuer ===")
reg_req = issuer.register_issuer()
print("Request 1:\n" + reg_req.get_print_string())
reg_resp = registry.process_request(reg_req)
print("Response 1:\n" + reg_resp.get_print_string())
issuer.process_request(reg_resp)
print("=== Done ===\n")

# 6 Entities parse bulk data from registry
print("=== Fetching bulk issuer details for verifier ===")
bulk_req = verifier.fetch_all_issuer_details()
print("Request 2:\n" + bulk_req.get_print_string())
bulk_resp = registry.process_request(bulk_req)
print("Response 2:\n" + bulk_resp.get_print_string())
verifier.process_request(bulk_resp)
print("=== Done ===\n")

print("=== Fetching bulk issuer details for holder ===")
bulk_req = holder.fetch_all_issuer_details()
print("Request 3:\n" + bulk_req.get_print_string())
bulk_resp = registry.process_request(bulk_req)
print("Response 3:\n" + bulk_resp.get_print_string())
holder.process_request(bulk_resp)
print("=== Done ===\n")

# == Printing execution status ==
print("Registry info:", registry.get_status_string())

print("Issuer info:", issuer.get_configuration())

print("Holder info:", holder.public_data_cache.get_cache_info())

print("Verifier info:", verifier.public_data_cache.get_cache_info())


### Credential Issuance ###
attributes = api.IssuanceAttributes()
attributes.append("name", "Ilya", api.AttributeType.REVEALED)
attributes.append("id", "123456", api.AttributeType.REVEALED)
attributes.append("age", "23", api.AttributeType.REVEALED)
attributes.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)

print("=== Requesting credential ===")
iss_req = holder.issuance_request("VeryCredible-University", attributes, "test-cred-1")
print("Request 4:\n" + iss_req.get_print_string())
freshness = issuer.process_request(iss_req)
print("Response 4:\n" + freshness.get_print_string())
blind_req = holder.process_request(freshness)
print("Response 5:\n" + blind_req.get_print_string())
forward_vc = issuer.process_request(blind_req)
print("Response 6:\n" + forward_vc.get_print_string())
holder.process_request(forward_vc)
print("=== Done ===\n")

print("Now holder has a credential!")
print("Holder's credentials:\n", holder.credentials["test-cred-1"][0].to_json())

print("Now we will try to use it")


### Verifier Requests Presentation
print("=== Requesting presentation ===")
presentation_req = verifier.presentation_request(["name", "id", "validUntil"])
print("Request 7:\n" + presentation_req.get_print_string())

presentation_resp = holder.present_credential(presentation_req, "test-cred-1", always_hidden_keys=["age", "LinkSecret"])
print("Response 7:\n" + presentation_resp.get_print_string())

valid, disclosed_messages, vp = verifier.process_request(presentation_resp)

print("Valid: ", valid)
print("Disclosed messages: ", disclosed_messages)
print("Verifiable Presentation: ", vp.to_json())
print("=== Done ===\n")



### Testing reissuance ###
print("Changing issuer parameters - reissuance window")
issuer.set_re_issuance_window_days(52)
print("Issuer info:", issuer.get_configuration())

print("=== Requesting reissuance ===")
reiss_req = holder.re_issuance_request("test-cred-1", always_hidden_keys=["LinkSecret"])
print("Request 8:\n" + reiss_req.get_print_string())
freshness_reiss = issuer.process_request(reiss_req)
print("Response 8:\n" + freshness_reiss.get_print_string())
blind_req_reiss = holder.process_request(freshness_reiss)
print("Response 9:\n" + blind_req_reiss.get_print_string())
forward_vc_reiss = issuer.process_request(blind_req_reiss)
print("Response 10:\n" + forward_vc_reiss.get_print_string())
holder.process_request(forward_vc_reiss)
print("=== Done ===\n")

print("Holder's credentials:\n", holder.credentials["test-cred-1"][0].to_json())