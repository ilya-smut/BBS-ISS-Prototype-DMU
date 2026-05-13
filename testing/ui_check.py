import time
import bbs_iss.demo.scripts.flask_bootstrap as bootstrap
from bbs_iss.ui.holder.app import create_holder_ui
from bbs_iss.ui.registry.app import create_registry_ui
from bbs_iss.ui.issuer.app import create_issuer_ui
from bbs_iss.ui.verifier.app import create_verifier_ui

verifier_orch = bootstrap.verifier_bootstrap()
registry_orch = bootstrap.registry_bootstrap()
issuer_orch = bootstrap.issuer_bootstrap(name="Test-University")
holder_orch = bootstrap.holder_bootstrap()

holder_app = create_holder_ui(orch=holder_orch)
registry_app = create_registry_ui(orch=registry_orch)
issuer_app = create_issuer_ui(orch=issuer_orch)
verifier_app = create_verifier_ui(orch=verifier_orch)

while True:
    time.sleep(1)