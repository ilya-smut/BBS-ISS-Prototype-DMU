"""
Edge-case tests for Flask transport layer.

Covers: server unreachable, HTTP timeout, listener dispatch
for unknown/unauthorized request types.
"""

import json
import time
import unittest
from threading import Thread

import requests as http_requests
from flask import Flask, request as flask_request

import bbs_iss.interfaces.requests_api as api
import bbs_iss.utils.utils as utils
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.endpoints.flask_endpoint import FlaskEndpoint
from bbs_iss.endpoints.flask_listener import FlaskListener
from bbs_iss.endpoints.orchestrator import (
    HolderOrchestrator,
    VerifierOrchestrator,
)
from bbs_iss.demo.demo_configuration import DefaultRoutes


# ── Module-level: slow server for timeout testing ────────────────────

_slow_app = Flask("slow_server")

@_slow_app.route(DefaultRoutes.PROCESS, methods=["POST"])
def _slow_handler():
    time.sleep(5)
    return "", 200

_slow_thread = Thread(
    target=_slow_app.run,
    kwargs={"host": "0.0.0.0", "port": 7099, "use_reloader": False},
    daemon=True,
)
_slow_thread.start()

# ── Module-level: listener without orchestrator ──────────────────────

_bare_holder = HolderInstance()
_bare_listener = FlaskListener(_bare_holder, port=7098)  # no orchestrator
_bare_listener.start()

_bare_verifier = VerifierInstance()
_bare_verifier_listener = FlaskListener(_bare_verifier, port=7097)  # no orchestrator
_bare_verifier_listener.start()

time.sleep(0.5)


# ═════════════════════════════════════════════════════════════════════════
# 1. Transport Failure Recovery
# ═════════════════════════════════════════════════════════════════════════

class TestServerUnreachable(unittest.TestCase):
    """Connection to a dead port should fail gracefully."""

    def test_issuance_to_dead_server(self):
        """Issuance against unreachable Issuer → FAILED, Holder resets."""
        issuer = IssuerInstance()
        issuer.set_issuer_parameters({"issuer": "Dead-Issuer"})
        holder = HolderInstance()

        # Pre-populate cache so issuance_request doesn't need registry
        holder.public_data_cache.update("Dead-Issuer", api.IssuerPublicData(
            issuer_name="Dead-Issuer",
            public_key=issuer.public_key,
            revocation_bitstring="ff",
            valid_until_weeks=7,
            validity_window_days=7,
        ))

        dead_ep = FlaskEndpoint("issuer", "http://localhost:9999", timeout=1)
        registry_ep = FlaskEndpoint("registry", "http://localhost:9999", timeout=1)
        h_orch = HolderOrchestrator(holder, issuer=dead_ep, registry=registry_ep)

        attrs = api.IssuanceAttributes()
        attrs.append("x", "v", api.AttributeType.REVEALED)
        attrs.append("LS", utils.gen_link_secret(), api.AttributeType.HIDDEN)

        trail = h_orch.execute_issuance("Dead-Issuer", attrs, "dead-cred")
        self.assertEqual(trail.status, "FAILED")
        self.assertTrue(holder.available)
        self.assertIn("Connection", trail.error)


class TestHTTPTimeout(unittest.TestCase):
    """Slow server should trigger ReadTimeout."""

    def test_timeout_triggers_failure(self):
        """1-second timeout against a 5-second handler → FAILED."""
        issuer = IssuerInstance()
        issuer.set_issuer_parameters({"issuer": "Slow-Issuer"})
        holder = HolderInstance()

        holder.public_data_cache.update("Slow-Issuer", api.IssuerPublicData(
            issuer_name="Slow-Issuer",
            public_key=issuer.public_key,
            revocation_bitstring="ff",
            valid_until_weeks=7,
            validity_window_days=7,
        ))

        slow_ep = FlaskEndpoint("issuer", "http://localhost:7099", timeout=1)
        registry_ep = FlaskEndpoint("registry", "http://localhost:9999", timeout=1)
        h_orch = HolderOrchestrator(holder, issuer=slow_ep, registry=registry_ep)

        attrs = api.IssuanceAttributes()
        attrs.append("x", "v", api.AttributeType.REVEALED)
        attrs.append("LS", utils.gen_link_secret(), api.AttributeType.HIDDEN)

        trail = h_orch.execute_issuance("Slow-Issuer", attrs, "slow-cred")
        self.assertEqual(trail.status, "FAILED")
        self.assertTrue(holder.available)
        self.assertIn("timed out", trail.error.lower())


# ═════════════════════════════════════════════════════════════════════════
# 2. Listener Dispatch Edge Cases
# ═════════════════════════════════════════════════════════════════════════

class TestListenerDispatch(unittest.TestCase):

    def test_vp_request_without_orchestrator_returns_501(self):
        """VP_REQUEST to a listener with no orchestrator → 501."""
        vp_req = api.VPRequest(["name"], utils.gen_nonce())
        resp = http_requests.post(
            f"http://localhost:7098{DefaultRoutes.PROCESS}",
            json=json.loads(vp_req.to_json()),
            timeout=5,
        )
        self.assertEqual(resp.status_code, 501)

    def test_forward_vp_without_orchestrator_returns_error(self):
        """FORWARD_VP to a listener with no orchestrator → error response."""
        # Craft a minimal ForwardVPResponse payload
        payload = {
            "request_type": api.RequestType.FORWARD_VP.value,
            "vp": {"context": [], "type": [], "verifiableCredential": {}},
            "pub_key": "aabb",
        }
        resp = http_requests.post(
            f"http://localhost:7097{DefaultRoutes.PROCESS}",
            json=payload,
            timeout=5,
        )
        # Deserialization fails or orchestrator missing → 500 or 501
        self.assertIn(resp.status_code, [500, 501])


if __name__ == "__main__":
    unittest.main()
