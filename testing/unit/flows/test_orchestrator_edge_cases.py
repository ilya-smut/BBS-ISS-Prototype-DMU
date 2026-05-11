"""
Edge-case tests for orchestrator-level behavior.

Uses LocalLoopback transport (in-process) unless noted.
Covers: ErrorResponse handling, entity state recovery, consent queue,
VP timeout, and trail integrity.
"""

import time
import unittest

import bbs_iss.interfaces.requests_api as api
import bbs_iss.utils.utils as utils
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.demo.local_demo_setup import create_local_demo


def _make_demo():
    issuer = IssuerInstance()
    issuer.set_issuer_parameters({"issuer": "Edge-Issuer"})
    issuer.set_epoch_size_days(49)
    issuer.set_re_issuance_window_days(7)
    holder = HolderInstance()
    verifier = VerifierInstance()
    registry = RegistryInstance()
    h, i, v, r = create_local_demo(issuer, holder, verifier, registry)
    i.register_with_registry()
    h.sync_registry()
    v.sync_registry()
    return issuer, holder, verifier, registry, h, i, v, r


def _issue(holder_orch, name="edge-cred"):
    attrs = api.IssuanceAttributes()
    attrs.append("name", "Alice", api.AttributeType.REVEALED)
    attrs.append("role", "Tester", api.AttributeType.REVEALED)
    attrs.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)
    trail = holder_orch.execute_issuance("Edge-Issuer", attrs, name)
    assert trail.status == "COMPLETED"


# ═════════════════════════════════════════════════════════════════════════
# 1. ErrorResponse Handling & Entity State Recovery
# ═════════════════════════════════════════════════════════════════════════

class TestErrorResponseHandling(unittest.TestCase):

    def test_error_at_freshness_resets_holder(self):
        """ISSUER_UNAVAILABLE at step 2 resets Holder to available."""
        issuer, holder, *_, h_orch, i_orch, v_orch, r_orch = _make_demo()
        issuer.freshness_response(api.RequestType.ISSUANCE)  # make busy

        attrs = api.IssuanceAttributes()
        attrs.append("x", "v", api.AttributeType.REVEALED)
        attrs.append("LS", utils.gen_link_secret(), api.AttributeType.HIDDEN)

        trail = h_orch.execute_issuance("Edge-Issuer", attrs, "fail")
        self.assertEqual(trail.status, "FAILED")
        self.assertIn("ISSUER_UNAVAILABLE", trail.error)
        self.assertTrue(holder.available)

    def test_retry_after_error_succeeds(self):
        """After a failed issuance, the same orchestrator can retry."""
        issuer, holder, *_, h_orch, i_orch, v_orch, r_orch = _make_demo()
        issuer.freshness_response(api.RequestType.ISSUANCE)

        attrs = api.IssuanceAttributes()
        attrs.append("x", "v", api.AttributeType.REVEALED)
        attrs.append("LS", utils.gen_link_secret(), api.AttributeType.HIDDEN)
        trail1 = h_orch.execute_issuance("Edge-Issuer", attrs, "fail")
        self.assertEqual(trail1.status, "FAILED")

        # Reset issuer, retry
        issuer.reset()
        attrs2 = api.IssuanceAttributes()
        attrs2.append("x", "v", api.AttributeType.REVEALED)
        attrs2.append("LS", utils.gen_link_secret(), api.AttributeType.HIDDEN)
        trail2 = h_orch.execute_issuance("Edge-Issuer", attrs2, "retry")
        self.assertEqual(trail2.status, "COMPLETED")
        self.assertTrue(holder.available)


# ═════════════════════════════════════════════════════════════════════════
# 2. Consent Queue Edge Cases
# ═════════════════════════════════════════════════════════════════════════

class TestConsentQueue(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        (cls.issuer, cls.holder, cls.verifier, cls.registry,
         cls.h_orch, cls.i_orch, cls.v_orch, cls.r_orch) = _make_demo()
        _issue(cls.h_orch, "consent-cred")

    def setUp(self):
        self.h_orch.pending_requests.clear()
        self.verifier.reset()

    def test_multiple_pending_requests(self):
        """Two VPRequests coexist; consenting to one leaves the other."""
        # Generate valid VPRequest via verifier (enters waiting state)
        req1 = self.verifier.presentation_request(["name"])
        req2 = api.VPRequest(["role"], utils.gen_nonce())  # stale, no verifier state
        self.h_orch.pending_requests.extend([req1, req2])

        trail, _ = self.h_orch.execute_presentation(
            req1, "consent-cred", always_hidden_keys=["LinkSecret"]
        )
        self.assertEqual(trail.status, "COMPLETED")
        self.assertEqual(len(self.h_orch.pending_requests), 1)
        self.assertEqual(self.h_orch.pending_requests[0].requested_attributes, ["role"])

    def test_duplicate_consent(self):
        """Consenting twice with different nonces works (credential valid)."""
        req = self.verifier.presentation_request(["name"])
        self.h_orch.pending_requests.append(req)

        trail1, _ = self.h_orch.execute_presentation(
            req, "consent-cred", always_hidden_keys=["LinkSecret"]
        )
        self.assertEqual(trail1.status, "COMPLETED")
        self.assertEqual(len(self.h_orch.pending_requests), 0)

        # Second consent with a fresh verifier request
        req2 = self.verifier.presentation_request(["name"])
        trail2, _ = self.h_orch.execute_presentation(
            req2, "consent-cred", always_hidden_keys=["LinkSecret"]
        )
        self.assertEqual(trail2.status, "COMPLETED")

    def test_stale_vp_request_after_reset(self):
        """VP sent after Verifier reset → fails gracefully, Holder resets."""
        # Verifier starts interaction then resets (simulating timeout)
        vp_req = self.v_orch.announce_presentation(["name"])
        self.verifier.reset()
        self.assertTrue(self.verifier.available)

        # Holder tries to present — Verifier rejects (not in interaction)
        self.h_orch.pending_requests.append(vp_req)
        trail, _ = self.h_orch.execute_presentation(
            vp_req, "consent-cred", always_hidden_keys=["LinkSecret"]
        )
        # Loopback send() calls verifier.process_request() which raises
        self.assertEqual(trail.status, "FAILED")
        self.assertTrue(self.holder.available)


# ═════════════════════════════════════════════════════════════════════════
# 3. VP Timeout
# ═════════════════════════════════════════════════════════════════════════

class TestVPTimeout(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        (cls.issuer, cls.holder, cls.verifier, cls.registry,
         cls.h_orch, cls.i_orch, cls.v_orch, cls.r_orch) = _make_demo()
        _issue(cls.h_orch, "timeout-cred")

    def setUp(self):
        self.verifier.reset()
        self.v_orch._vp_timeout_seconds = None
        self.v_orch._cancel_timeout()

    def test_timeout_cancelled_by_response(self):
        """VP arriving before timeout keeps Verifier in valid state."""
        self.v_orch._vp_timeout_seconds = 2
        vp_req = self.v_orch.announce_presentation(["name"])

        # Present before timeout
        fwd_vp = self.holder.present_credential(
            vp_req, "timeout-cred", always_hidden_keys=["LinkSecret"]
        )
        result = self.v_orch.complete_presentation(fwd_vp)
        self.assertTrue(result[0])  # valid
        self.assertTrue(self.verifier.available)  # reset by complete_presentation

        # Wait past timeout — should NOT reset (timer was cancelled)
        time.sleep(2.5)
        self.assertTrue(self.verifier.available)

    def test_double_request_after_timeout(self):
        """After timeout, Verifier can issue a new VPRequest."""
        self.v_orch._vp_timeout_seconds = 1
        self.v_orch.announce_presentation(["name"])
        self.assertFalse(self.verifier.available)

        time.sleep(1.5)
        self.assertTrue(self.verifier.available)

        # Second request should work
        vp_req2 = self.v_orch.announce_presentation(["role"])
        self.assertFalse(self.verifier.available)
        self.assertEqual(vp_req2.requested_attributes, ["role"])

        self.verifier.reset()


# ═════════════════════════════════════════════════════════════════════════
# 4. Trail Integrity
# ═════════════════════════════════════════════════════════════════════════

class TestTrailIntegrity(unittest.TestCase):

    def test_failed_trail_records_all_steps(self):
        """A failure at step N should still have N-1 recorded entries."""
        issuer, holder, *_, h_orch, i_orch, v_orch, r_orch = _make_demo()
        _issue(h_orch, "trail-cred")

        # Make issuer busy so re-issuance fails at freshness step
        issuer.freshness_response(api.RequestType.RE_ISSUANCE)

        trail = h_orch.execute_re_issuance("trail-cred", ["LinkSecret"])
        self.assertEqual(trail.status, "FAILED")
        # Should have: [1] re-issuance request, [2] error response
        self.assertGreaterEqual(len(trail.entries), 2)
        self.assertIsNotNone(trail.error)

    def test_completed_trail_has_all_steps(self):
        """Successful issuance trail should have 4 entries."""
        *_, h_orch, i_orch, v_orch, r_orch = _make_demo()

        attrs = api.IssuanceAttributes()
        attrs.append("x", "v", api.AttributeType.REVEALED)
        attrs.append("LS", utils.gen_link_secret(), api.AttributeType.HIDDEN)
        trail = h_orch.execute_issuance("Edge-Issuer", attrs, "full-trail")

        self.assertEqual(trail.status, "COMPLETED")
        self.assertEqual(len(trail.entries), 4)
        types = [e.request_type for e in trail.entries]
        self.assertEqual(types, ["ISSUANCE", "FRESHNESS", "BLIND_SIGN", "FORWARD_VC"])


if __name__ == "__main__":
    unittest.main()
