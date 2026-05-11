"""
Integration tests for the Orchestrator layer.

Tests all protocol flows through orchestrators wired with
LocalLoopbackEndpoints, validating that the orchestrator routing
logic and JSON serialization round-trips work correctly.
"""

import unittest
import bbs_iss.interfaces.requests_api as api
import bbs_iss.utils.utils as utils
from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance
from bbs_iss.entities.entity import Entity
from bbs_iss.endpoints.demo_setup import create_local_demo


class TestEntityABC(unittest.TestCase):
    """Verify that all entity classes satisfy the Entity ABC contract."""

    def test_holder_is_entity(self):
        holder = HolderInstance()
        self.assertIsInstance(holder, Entity)
        self.assertTrue(holder.available)

    def test_issuer_is_entity(self):
        issuer = IssuerInstance()
        self.assertIsInstance(issuer, Entity)
        self.assertTrue(issuer.available)

    def test_verifier_is_entity(self):
        verifier = VerifierInstance()
        self.assertIsInstance(verifier, Entity)
        self.assertTrue(verifier.available)

    def test_registry_is_entity(self):
        registry = RegistryInstance()
        self.assertIsInstance(registry, Entity)
        self.assertTrue(registry.available)
        registry.reset()  # Should be a no-op
        self.assertTrue(registry.available)


class OrchestratorTestBase(unittest.TestCase):
    """Common setup for orchestrator integration tests."""

    def setUp(self):
        self.registry = RegistryInstance()
        self.issuer = IssuerInstance()
        self.issuer.set_issuer_parameters({"issuer": "Test-University"})
        self.issuer.set_epoch_size_days(49)
        self.issuer.set_re_issuance_window_days(7)

        self.holder = HolderInstance()
        self.verifier = VerifierInstance()

        self.holder_orch, self.issuer_orch, self.verifier_orch, self.registry_orch = \
            create_local_demo(self.issuer, self.holder, self.verifier, self.registry)

    def _register_and_sync(self):
        """Register issuer and sync all caches."""
        self.issuer_orch.register_with_registry()
        self.holder_orch.sync_registry()
        self.verifier_orch.sync_registry()


class TestRegistryFlows(OrchestratorTestBase):
    """Test registry administrative flows through orchestrators."""

    def test_issuer_registration(self):
        trail = self.issuer_orch.register_with_registry()
        self.assertEqual(trail.status, "COMPLETED")
        self.assertEqual(trail.protocol, "REGISTRY_REGISTRATION")
        self.assertGreater(len(trail.entries), 0)

    def test_issuer_update(self):
        self.issuer_orch.register_with_registry()
        trail = self.issuer_orch.update_registry()
        self.assertEqual(trail.status, "COMPLETED")
        self.assertEqual(trail.protocol, "REGISTRY_UPDATE")

    def test_holder_sync(self):
        self.issuer_orch.register_with_registry()
        trail = self.holder_orch.sync_registry()
        self.assertEqual(trail.status, "COMPLETED")
        self.assertIn("Test-University", self.holder.public_data_cache._cache)

    def test_verifier_sync(self):
        self.issuer_orch.register_with_registry()
        trail = self.verifier_orch.sync_registry()
        self.assertEqual(trail.status, "COMPLETED")
        self.assertIn("Test-University", self.verifier.public_data_cache._cache)

    def test_registry_status(self):
        self.issuer_orch.register_with_registry()
        status = self.registry_orch.get_status()
        self.assertIn("Test-University", status)

    def test_issuer_configuration_proxy(self):
        config = self.issuer_orch.get_configuration()
        self.assertIn("Test-University", config)


class TestIssuanceFlow(OrchestratorTestBase):
    """Test full issuance protocol through HolderOrchestrator."""

    def _build_attributes(self):
        attributes = api.IssuanceAttributes()
        attributes.append("name", "Alice", api.AttributeType.REVEALED)
        attributes.append("id", "999", api.AttributeType.REVEALED)
        attributes.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)
        return attributes

    def test_issuance_success(self):
        self._register_and_sync()

        attributes = self._build_attributes()
        trail = self.holder_orch.execute_issuance(
            "Test-University", attributes, "test-cred"
        )

        self.assertEqual(trail.status, "COMPLETED")
        self.assertEqual(trail.protocol, "ISSUANCE")
        self.assertIn("test-cred", self.holder.credentials)

        # Verify trail has multiple steps
        self.assertGreater(len(trail.entries), 3)

    def test_issuance_trail_print(self):
        self._register_and_sync()

        attributes = self._build_attributes()
        trail = self.holder_orch.execute_issuance(
            "Test-University", attributes, "test-cred"
        )

        # Compact trail
        compact = trail.print_trail(verbose=False)
        self.assertIn("ISSUANCE", compact)
        self.assertIn("COMPLETED", compact)

        # Verbose trail
        verbose = trail.print_trail(verbose=True)
        self.assertIn("ISSUANCE", verbose)
        # Verbose output should be longer
        self.assertGreater(len(verbose), len(compact))

    def test_issuance_with_registry_resolution(self):
        """Test issuance when holder cache is empty (triggers registry lookup)."""
        self.issuer_orch.register_with_registry()
        # Deliberately do NOT sync holder cache — force cache miss

        attributes = self._build_attributes()
        trail = self.holder_orch.execute_issuance(
            "Test-University", attributes, "test-cred"
        )

        self.assertEqual(trail.status, "COMPLETED")
        self.assertIn("test-cred", self.holder.credentials)

        # Trail should include registry resolution steps
        request_types = [e.request_type for e in trail.entries]
        self.assertIn("GET_ISSUER_DETAILS", request_types)


class TestPresentationFlow(OrchestratorTestBase):
    """Test the split presentation protocol (Announcement + Execution)."""

    def setUp(self):
        super().setUp()
        self._register_and_sync()
        self._issue_credential()

    def _issue_credential(self):
        attributes = api.IssuanceAttributes()
        attributes.append("name", "Alice", api.AttributeType.REVEALED)
        attributes.append("id", "999", api.AttributeType.REVEALED)
        attributes.append("age", "25", api.AttributeType.REVEALED)
        attributes.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)

        self.holder_orch.execute_issuance(
            "Test-University", attributes, "test-cred"
        )

    def test_split_presentation(self):
        """Test the announce → execute → complete flow."""
        # Verifier announces
        vp_request = self.verifier_orch.announce_presentation(
            ["name", "id", "validUntil"]
        )
        self.assertIsInstance(vp_request, api.VPRequest)
        self.assertEqual(vp_request.requested_attributes, ["name", "id", "validUntil"])

        # Holder executes (after consent) — returns VP, doesn't send it
        trail, forward_vp = self.holder_orch.execute_presentation(
            vp_request, "test-cred", always_hidden_keys=["LinkSecret"]
        )
        self.assertEqual(trail.status, "COMPLETED")
        self.assertEqual(trail.protocol, "PRESENTATION_EXECUTION")
        self.assertIsNotNone(forward_vp)
        self.assertIsInstance(forward_vp, api.ForwardVPResponse)

        # Verifier completes — caller delivers the VP
        valid, attrs, vp = self.verifier_orch.complete_presentation(forward_vp)
        self.assertTrue(valid)
        self.assertIn("name", attrs)

    def test_presentation_with_validity_check(self):
        """Test that presented attributes are correct."""
        vp_request = self.verifier_orch.announce_presentation(
            ["name", "id", "validUntil"]
        )

        # Holder executes via orchestrator
        trail, forward_vp = self.holder_orch.execute_presentation(
            vp_request, "test-cred", always_hidden_keys=["LinkSecret"]
        )

        # Complete presentation via verifier orchestrator
        valid, attrs, vp = self.verifier_orch.complete_presentation(forward_vp)
        self.assertTrue(valid)
        self.assertIn("name", attrs)
        self.assertEqual(attrs["name"], "Alice")
        self.assertIn("validUntil", attrs)


class TestReIssuanceFlow(OrchestratorTestBase):
    """Test credential re-issuance through HolderOrchestrator."""

    def setUp(self):
        super().setUp()
        self._register_and_sync()
        self._issue_credential()

    def _issue_credential(self):
        attributes = api.IssuanceAttributes()
        attributes.append("name", "Bob", api.AttributeType.REVEALED)
        attributes.append("id", "777", api.AttributeType.REVEALED)
        attributes.append("LinkSecret", utils.gen_link_secret(), api.AttributeType.HIDDEN)

        self.holder_orch.execute_issuance(
            "Test-University", attributes, "bob-cred"
        )

    def test_re_issuance_success(self):
        # Widen window to make re-issuance eligible
        self.issuer.set_re_issuance_window_days(52)

        trail = self.holder_orch.execute_re_issuance(
            "bob-cred", always_hidden_keys=["LinkSecret"]
        )

        self.assertEqual(trail.status, "COMPLETED")
        self.assertEqual(trail.protocol, "RE_ISSUANCE")

        # Credential should still exist with updated validity
        self.assertIn("bob-cred", self.holder.credentials)

    def test_re_issuance_trail_steps(self):
        self.issuer.set_re_issuance_window_days(52)

        trail = self.holder_orch.execute_re_issuance(
            "bob-cred", always_hidden_keys=["LinkSecret"]
        )

        # Should have multiple steps
        self.assertGreater(len(trail.entries), 3)
        request_types = [e.request_type for e in trail.entries]
        self.assertIn("RE_ISSUANCE", request_types)
        self.assertIn("FRESHNESS", request_types)


class TestRequestTrail(unittest.TestCase):
    """Unit tests for RequestTrail functionality."""

    def test_empty_trail(self):
        from bbs_iss.endpoints.trail import RequestTrail
        trail = RequestTrail(protocol="TEST")
        self.assertEqual(trail.status, "IN_PROGRESS")
        self.assertEqual(len(trail.entries), 0)
        self.assertIsNone(trail.last_response)

    def test_record_and_complete(self):
        from bbs_iss.endpoints.trail import RequestTrail
        trail = RequestTrail(protocol="TEST")
        msg = api.VCIssuanceRequest()
        trail.record("Holder", "Issuer", msg)
        self.assertEqual(len(trail.entries), 1)
        self.assertEqual(trail.entries[0].sender, "Holder")
        self.assertEqual(trail.entries[0].receiver, "Issuer")
        self.assertEqual(trail.entries[0].request_type, "ISSUANCE")
        trail.mark_completed()
        self.assertEqual(trail.status, "COMPLETED")

    def test_mark_failed(self):
        from bbs_iss.endpoints.trail import RequestTrail
        trail = RequestTrail(protocol="TEST")
        err = api.ErrorResponse(
            api.RequestType.ISSUANCE,
            api.ErrorType.ISSUER_UNAVAILABLE,
            message="Busy"
        )
        trail.record("Issuer", "Holder", err)
        trail.mark_failed(err)
        self.assertEqual(trail.status, "FAILED")
        self.assertIn("ISSUER_UNAVAILABLE", trail.error)

    def test_print_trail_compact(self):
        from bbs_iss.endpoints.trail import RequestTrail
        trail = RequestTrail(protocol="TEST")
        trail.record("A", "B", api.VCIssuanceRequest())
        trail.mark_completed()
        output = trail.print_trail(verbose=False)
        self.assertIn("TEST", output)
        self.assertIn("COMPLETED", output)
        self.assertIn("A -> B", output)

    def test_print_trail_verbose(self):
        from bbs_iss.endpoints.trail import RequestTrail
        trail = RequestTrail(protocol="TEST")
        trail.record("A", "B", api.VCIssuanceRequest())
        trail.mark_completed()
        verbose = trail.print_trail(verbose=True)
        compact = trail.print_trail(verbose=False)
        self.assertGreater(len(verbose), len(compact))


if __name__ == "__main__":
    unittest.main()
