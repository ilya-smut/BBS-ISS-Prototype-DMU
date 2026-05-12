#!/usr/bin/env python3
"""Docker entrypoint for the Issuer container."""

import os
import signal
import time

from bbs_iss.demo.demo_configuration import DefaultPorts
from bbs_iss.demo.scripts.flask_bootstrap import issuer_bootstrap
from bbs_iss.ui.issuer.app import create_issuer_ui

orch = issuer_bootstrap(
    name=os.environ.get("ISSUER_NAME", "Issuer"),
    issuer_port=int(os.environ.get("ISSUER_PORT", DefaultPorts.ISSUER)),
    registry_base=os.environ.get("REGISTRY_BASE", "http://localhost"),
    registry_port=int(os.environ.get("REGISTRY_PORT", DefaultPorts.REGISTRY)),
)

ui_port = int(os.environ.get("ISSUER_UI_PORT", 8002))
create_issuer_ui(orch, port=ui_port)

print(f"[Issuer] Protocol listener on 0.0.0.0:{os.environ.get('ISSUER_PORT', DefaultPorts.ISSUER)}")
print(f"[Issuer] UI available at http://0.0.0.0:{ui_port}")

signal.signal(signal.SIGTERM, lambda *_: exit(0))
while True:
    time.sleep(1)
