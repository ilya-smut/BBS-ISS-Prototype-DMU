#!/usr/bin/env python3
"""Docker entrypoint for the Registry container."""

import os
import signal
import time

from bbs_iss.demo.demo_configuration import DefaultPorts
from bbs_iss.demo.scripts.flask_bootstrap import registry_bootstrap
from bbs_iss.ui.registry.app import create_registry_ui

orch = registry_bootstrap(
    registry_port=int(os.environ.get("REGISTRY_PORT", DefaultPorts.REGISTRY)),
)

ui_port = int(os.environ.get("REGISTRY_UI_PORT", 8001))
create_registry_ui(orch, port=ui_port)

print(f"[Registry] Protocol listener on 0.0.0.0:{os.environ.get('REGISTRY_PORT', DefaultPorts.REGISTRY)}")
print(f"[Registry] UI available at http://0.0.0.0:{ui_port}")

signal.signal(signal.SIGTERM, lambda *_: exit(0))
while True:
    time.sleep(1)
