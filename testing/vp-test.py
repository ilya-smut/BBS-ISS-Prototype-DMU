import bbs_iss.interfaces.requests_api as api
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance

import bbs_iss.utils.utils as utils

issuer = IssuerInstance()
pub_key = issuer.public_key
holder = HolderInstance()
attributes = api.IssuanceAttributes()
attributes.append("secret", utils.gen_link_secret(), api.AttributeType.HIDDEN)
attributes.append("not_secret", "very not secret", api.AttributeType.REVEALED)
attributes.append("name", "Alice", api.AttributeType.REVEALED)
attributes.append("studentId", "S-001", api.AttributeType.REVEALED)

# Request to Issuer
init_request = holder.issuance_request(issuer_pub_key=pub_key, attributes=attributes, cred_name="test-cred")

# Process Request -> send Freshness Response
freshness_response = issuer.process_request(init_request)

# Process Freshness Response -> send Blind Sign Request
blind_sign_request = holder.process_request(freshness_response)

# Process Blind Sign Response -> send Forward VC Response
forward_vc_response = issuer.process_request(blind_sign_request)

# Verify VC
print(holder.process_request(forward_vc_response))

# Check if the cred is present
print(holder.credentials["test-cred"][0].to_json())

verifier = VerifierInstance()

# Create VP Request
VP_request = verifier.presentation_request(requested_attributes=["studentId", "name", "validUntil"])

# Send Forward VP Request
VP_response = holder.present_credential(vp_request=VP_request, vc_name="test-cred", always_hidden_keys=["secret", "revocationMaterial"])

# Forward VP Response to Verifier. Verifier checks if the VP is valid
result = verifier.process_request(VP_response)
print(result[0])
print(result[1])