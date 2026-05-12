#!/usr/bin/env python3
"""Docker entrypoint for the Holder container."""

import os
import signal
import time

from bbs_iss.demo.demo_configuration import DefaultPorts
from bbs_iss.demo.scripts.flask_bootstrap import holder_bootstrap
from bbs_iss.ui.holder.app import create_holder_ui

orch = holder_bootstrap(
    holder_port=int(os.environ.get("HOLDER_PORT", DefaultPorts.HOLDER)),
    issuer_base=os.environ.get("ISSUER_BASE", "http://localhost"),
    issuer_port=int(os.environ.get("ISSUER_PORT", DefaultPorts.ISSUER)),
    verifier_base=os.environ.get("VERIFIER_BASE", "http://localhost"),
    verifier_port=int(os.environ.get("VERIFIER_PORT", DefaultPorts.VERIFIER)),
    registry_base=os.environ.get("REGISTRY_BASE", "http://localhost"),
    registry_port=int(os.environ.get("REGISTRY_PORT", DefaultPorts.REGISTRY)),
)

ui_port = int(os.environ.get("HOLDER_UI_PORT", 8004))
create_holder_ui(orch, port=ui_port)

print(f"[Holder] Protocol listener on 0.0.0.0:{os.environ.get('HOLDER_PORT', DefaultPorts.HOLDER)}")
print(f"[Holder] UI available at http://0.0.0.0:{ui_port}")

signal.signal(signal.SIGTERM, lambda *_: exit(0))
while True:
    time.sleep(1)
