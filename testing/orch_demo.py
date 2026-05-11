from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance

import bbs_iss.utils.utils as utils

import bbs_iss.interfaces.requests_api as api
from bbs_iss.demo.local_demo_setup import create_local_demo


issuer = IssuerInstance()
issuer.set_issuer_parameters({"issuer": "Test-University"})
holder = HolderInstance()
verifier = VerifierInstance()
registry = RegistryInstance()

holder_orch, issuer_orch, verifier_orch, registry_orch = create_local_demo(
    issuer, holder, verifier, registry
)
reg_trail = issuer_orch.register_with_registry()
print(reg_trail.print_trail(verbose=True))

attributes = api.IssuanceAttributes()
attributes.append("name", "Ilya", api.AttributeType.REVEALED)
attributes.append("lastname", "Smut", api.AttributeType.REVEALED)
attributes.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)

cred_issue_trail = holder_orch.execute_issuance("Test-University", attributes, "test-cred")
print(cred_issue_trail.print_trail(verbose=True))

failed_cred_trail = holder_orch.execute_issuance("Gibberish", attributes, "test-cred-2")
print(failed_cred_trail.print_trail(verbose=True))

requested_attributes = ["name", "lastname"]

pres_request = verifier_orch.announce_presentation(requested_attributes)
pres_issue_trail, pres_response = holder_orch.execute_presentation(pres_request, "test-cred")
print(pres_issue_trail.print_trail(verbose=True))

valid, attrs, vp = verifier_orch.complete_presentation(pres_response)
print(valid, attrs, vp)