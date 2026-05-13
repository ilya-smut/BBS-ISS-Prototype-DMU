#!/usr/bin/env python3
"""Docker entrypoint for the Verifier container."""

import os
import signal
import time

from bbs_iss.demo.demo_configuration import DefaultPorts
from bbs_iss.demo.scripts.flask_bootstrap import verifier_bootstrap
from bbs_iss.ui.verifier import create_verifier_ui

orch = verifier_bootstrap(
    verifier_port=int(os.environ.get("VERIFIER_PORT", DefaultPorts.VERIFIER)),
    holder_base=os.environ.get("HOLDER_BASE", "http://localhost"),
    holder_port=int(os.environ.get("HOLDER_PORT", DefaultPorts.HOLDER)),
    registry_base=os.environ.get("REGISTRY_BASE", "http://localhost"),
    registry_port=int(os.environ.get("REGISTRY_PORT", DefaultPorts.REGISTRY)),
)

create_verifier_ui(orch, port=8003)

print(f"[Verifier] Listening on 0.0.0.0:{os.environ.get('VERIFIER_PORT', DefaultPorts.VERIFIER)}")
print(f"[Verifier] UI available at http://localhost:8003")

signal.signal(signal.SIGTERM, lambda *_: exit(0))
while True:
    time.sleep(1)

