#!/usr/bin/env python3
"""Docker entrypoint for the Registry container."""

import os
import signal
import time

from bbs_iss.demo.demo_configuration import DefaultPorts
from bbs_iss.demo.scripts.flask_bootstrap import registry_bootstrap

orch = registry_bootstrap(
    registry_port=int(os.environ.get("REGISTRY_PORT", DefaultPorts.REGISTRY)),
)

print(f"[Registry] Listening on 0.0.0.0:{os.environ.get('REGISTRY_PORT', DefaultPorts.REGISTRY)}")

signal.signal(signal.SIGTERM, lambda *_: exit(0))
while True:
    time.sleep(1)
