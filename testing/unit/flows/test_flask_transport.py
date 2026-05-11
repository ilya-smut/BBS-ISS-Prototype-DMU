"""
Integration tests for Flask-based transport.

Verifies that the full protocol lifecycle works correctly
over real HTTP transport (FlaskEndpoint + FlaskListener).

All test classes share a single set of Flask servers started
at module load time to avoid port conflicts.
"""

import time
import unittest

import bbs_iss.interfaces.requests_api as api
import bbs_iss.utils.utils as utils
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.demo.flask_demo_setup import create_flask_demo


# ── Module-level setup: start Flask servers once ─────────────────────────

_issuer = IssuerInstance()
_issuer.set_issuer_parameters({"issuer": "Flask-Test-Issuer"})
_issuer.set_epoch_size_days(49)
_issuer.set_re_issuance_window_days(7)

_holder = HolderInstance()
_verifier = VerifierInstance()
_registry = RegistryInstance()

_holder_orch, _issuer_orch, _verifier_orch, _registry_orch = create_flask_demo(
    _issuer, _holder, _verifier, _registry,
    issuer_port=6001, verifier_port=6002,
    registry_port=6003, holder_port=6004,
)

# Bootstrap: register issuer and sync caches
_issuer_orch.register_with_registry()
_holder_orch.sync_registry()
_verifier_orch.sync_registry()


class TestFlaskIssuance(unittest.TestCase):
    """Test credential issuance over Flask HTTP endpoints."""

    def test_issuance_over_http(self):
        """Full issuance round-trip should succeed over HTTP."""
        attributes = api.IssuanceAttributes()
        attributes.append("name", "Bob", api.AttributeType.REVEALED)
        attributes.append("role", "Tester", api.AttributeType.REVEALED)
        attributes.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)

        trail = _holder_orch.execute_issuance(
            "Flask-Test-Issuer", attributes, "flask-issuance-cred"
        )
        self.assertEqual(trail.status, "COMPLETED")
        self.assertEqual(trail.protocol, "ISSUANCE")
        self.assertGreater(len(trail.entries), 0)


class TestFlaskPresentation(unittest.TestCase):
    """Test presentation flow with consent checkpoint over HTTP."""

    @classmethod
    def setUpClass(cls):
        # Issue a credential for presentation tests
        attributes = api.IssuanceAttributes()
        attributes.append("name", "Alice", api.AttributeType.REVEALED)
        attributes.append("department", "CS", api.AttributeType.REVEALED)
        attributes.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)

        _holder_orch.execute_issuance(
            "Flask-Test-Issuer", attributes, "flask-pres-cred"
        )

    def test_pending_queue_populated(self):
        """VPRequest sent via HTTP should appear in Holder's pending queue."""
        trail, vp_request = _verifier_orch.send_presentation_request(["name"])
        self.assertEqual(trail.status, "COMPLETED")

        time.sleep(0.3)
        pending = _holder_orch.get_pending_requests()
        self.assertGreater(len(pending), 0)
        self.assertEqual(pending[-1].requested_attributes, ["name"])

        # Clean up: reset verifier state so other tests aren't blocked
        _verifier.reset()
        _holder_orch.pending_requests.clear()

    def test_full_presentation_over_http(self):
        """Full presentation with consent: queue → consent → auto-send → verify."""
        # Verifier sends VPRequest to Holder
        trail, vp_request = _verifier_orch.send_presentation_request(
            ["name", "department"]
        )
        self.assertEqual(trail.status, "COMPLETED")

        time.sleep(0.3)

        # Holder reviews and consents
        pending = _holder_orch.get_pending_requests()
        self.assertGreater(len(pending), 0)

        pres_trail, forward_vp = _holder_orch.execute_presentation(
            pending[-1], "flask-pres-cred", always_hidden_keys=["LinkSecret"]
        )
        self.assertEqual(pres_trail.status, "COMPLETED")
        self.assertIsNotNone(forward_vp)

        # Check verification result on Verifier side
        time.sleep(0.3)
        self.assertGreater(len(_verifier_orch.verification_results), 0)
        valid, attrs, vp = _verifier_orch.verification_results[-1]
        self.assertTrue(valid)
        self.assertIn("name", attrs)
        self.assertEqual(attrs["name"], "Alice")
        self.assertIn("department", attrs)


class TestFlaskVerifierTimeout(unittest.TestCase):
    """Test that Verifier VP timeout resets state via orchestrator timer."""

    def test_timeout_resets_verifier_state(self):
        """After timeout expires, verifier should be available again."""
        # Set very short timeout for testing
        _verifier_orch._vp_timeout_seconds = 1

        # Announce presentation (puts verifier in waiting state)
        vp_request = _verifier_orch.announce_presentation(["name"])
        self.assertFalse(_verifier.available)

        # Wait for timeout to fire
        time.sleep(1.5)
        self.assertTrue(_verifier.available)

        # Reset timeout for other tests
        _verifier_orch._vp_timeout_seconds = None


if __name__ == "__main__":
    unittest.main()
