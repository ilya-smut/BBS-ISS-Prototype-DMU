from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
import bbs_iss.interfaces.requests_api as api
import os
issuer = IssuerInstance()
pub_key = issuer.public_key
holder = HolderInstance()
attributes = api.IssuanceAttributes()
attributes.append("secret", os.urandom(32), api.AttributeType.HIDDEN)
attributes.append("not_secret", "very not secret", api.AttributeType.REVEALED)

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