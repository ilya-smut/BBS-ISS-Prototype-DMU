"""
Networked demo: entities communicate over Flask HTTP endpoints.

Topology (single machine, different ports):
  - Registry:  http://localhost:5003/process
  - Issuer:    http://localhost:5001/process
  - Verifier:  http://localhost:5002/process
  - Holder:    http://localhost:5004/process

Demonstrates:
  1. Registry registration (Issuer → Registry over HTTP)
  2. Cache sync (Holder/Verifier → Registry over HTTP)
  3. Credential issuance (Holder ↔ Issuer, multi-round-trip HTTP)
  4. Presentation with consent checkpoint:
     - Verifier sends VPRequest to Holder (HTTP fire-and-forget)
     - Holder queues the request (pending consent)
     - Holder reviews, consents, and auto-sends VP to Verifier (HTTP)
     - Verifier processes VP and stores verification result
"""

import time
import bbs_iss.interfaces.requests_api as api
import bbs_iss.utils.utils as utils
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.demo.flask_demo_setup import create_flask_demo


# ── Entity setup ─────────────────────────────────────────────────────────
issuer = IssuerInstance()
issuer.set_issuer_parameters({"issuer": "Test-University"})
issuer.set_epoch_size_days(49)
issuer.set_re_issuance_window_days(7)

holder = HolderInstance()
verifier = VerifierInstance()
registry = RegistryInstance()

print("Starting Flask servers...")
holder_orch, issuer_orch, verifier_orch, registry_orch = create_flask_demo(
    issuer, holder, verifier, registry
)
print("All servers running.\n")

# ── 1. Register Issuer with Registry (HTTP) ──────────────────────────────
print("=" * 60)
print("  STEP 1: Issuer Registration")
print("=" * 60)
reg_trail = issuer_orch.register_with_registry()
print(reg_trail.print_trail(verbose=True))

# ── 2. Sync caches (HTTP) ───────────────────────────────────────────────
print("=" * 60)
print("  STEP 2: Cache Sync")
print("=" * 60)
holder_orch.sync_registry()
verifier_orch.sync_registry()
print("Holder and Verifier caches synced.\n")

# ── 3. Issue credential (multi-round-trip HTTP) ─────────────────────────
print("=" * 60)
print("  STEP 3: Credential Issuance (over HTTP)")
print("=" * 60)
attributes = api.IssuanceAttributes()
attributes.append("name", "Ilya", api.AttributeType.REVEALED)
attributes.append("lastname", "Smut", api.AttributeType.REVEALED)
attributes.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)

cred_trail = holder_orch.execute_issuance("Test-University", attributes, "test-cred")
print(cred_trail.print_trail(verbose=True))

# ── 4. Presentation with consent checkpoint ──────────────────────────────
print("=" * 60)
print("  STEP 4: Presentation (with consent checkpoint)")
print("=" * 60)

# 4a. Verifier generates VPRequest and sends it to Holder's /process
print("Verifier sending VP request to Holder...")
req_trail, vp_request = verifier_orch.send_presentation_request(["name", "lastname"])
print(req_trail.print_trail(verbose=True))

# 4b. Holder reviews pending requests (consent checkpoint)
time.sleep(0.2)  # Brief pause for request to arrive
pending = holder_orch.get_pending_requests()
print(f"Holder has {len(pending)} pending VP request(s).")
if pending:
    print(f"Requested attributes: {pending[0].requested_attributes}")
    print("Holder reviewing and giving consent...\n")

    # 4c. Holder consents → builds VP → auto-sends to Verifier's /process
    pres_trail, forward_vp = holder_orch.execute_presentation(
        pending[0], "test-cred", always_hidden_keys=["LinkSecret"]
    )
    print(pres_trail.print_trail(verbose=True))

    # 4d. Check verification result on Verifier side
    time.sleep(0.2)  # Brief pause for VP to be processed
    if verifier_orch.verification_results:
        valid, attrs, vp = verifier_orch.verification_results[-1]
        print(f"\nVerifier verification result: valid={valid}")
        print(f"Disclosed attributes: {attrs}")
    else:
        print("\nNo verification results yet.")
else:
    print("No pending requests — something went wrong.")

print("\n" + "=" * 60)
print("  Demo complete.")
print("=" * 60)
