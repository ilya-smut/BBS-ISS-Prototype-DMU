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
reg_req = issuer.register_issuer()
reg_resp = registry.process_request(reg_req)
issuer.process_request(reg_resp)

# 6 Entities parse bulk data from registry
bulk_req = verifier.fetch_all_issuer_details()
bulk_resp = registry.process_request(bulk_req)
verifier.process_request(bulk_resp)

bulk_req = holder.fetch_all_issuer_details()
bulk_resp = registry.process_request(bulk_req)
holder.process_request(bulk_resp)

# == Printing execution status ==
print("Registry info:", registry.get_status_string())

print("Issuer info:", issuer.get_configuration())

print("Holder info:", holder.public_data_cache.get_cache_info())

print("Verifier info:", verifier.public_data_cache.get_cache_info())



