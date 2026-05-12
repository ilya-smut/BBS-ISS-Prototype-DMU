#!/usr/bin/env python3
"""Docker entrypoint for the Issuer container."""

import os
import signal
import time

from bbs_iss.demo.demo_configuration import DefaultPorts
from bbs_iss.demo.scripts.flask_bootstrap import issuer_bootstrap

orch = issuer_bootstrap(
    issuer_port=int(os.environ.get("ISSUER_PORT", DefaultPorts.ISSUER)),
    registry_base=os.environ.get("REGISTRY_BASE", "http://localhost"),
    registry_port=int(os.environ.get("REGISTRY_PORT", DefaultPorts.REGISTRY)),
)

print(f"[Issuer] Listening on 0.0.0.0:{os.environ.get('ISSUER_PORT', DefaultPorts.ISSUER)}")

signal.signal(signal.SIGTERM, lambda *_: exit(0))
while True:
    time.sleep(1)
