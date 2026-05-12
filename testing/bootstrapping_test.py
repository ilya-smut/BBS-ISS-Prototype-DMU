from bbs_iss.demo.scripts.flask_bootstrap import verifier_bootstrap
import bbs_iss.demo.scripts.flask_bootstrap as bootstrap
import bbs_iss.interfaces.requests_api as api
import bbs_iss.utils.utils as utils

holder_orch = bootstrap.holder_bootstrap()
verifier_orch = bootstrap.verifier_bootstrap()
registry_orch = bootstrap.registry_bootstrap()
issuer_orch = bootstrap.issuer_bootstrap(name="Test-University")

reg_trail = issuer_orch.register_with_registry()
print(reg_trail.print_trail())

attr = api.IssuanceAttributes()
attr.append("name", "Ilya", api.AttributeType.REVEALED)
attr.append("lastname", "Smut", api.AttributeType.REVEALED)
attr.append("dob", "07-09-2003", api.AttributeType.REVEALED)
attr.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)

issue_trail = holder_orch.execute_issuance(issuer_name="Test-University", attributes=attr, cred_name="cred-1")
print(issue_trail.print_trail())
print(holder_orch.entity.credentials["cred-1"][0].to_json())
