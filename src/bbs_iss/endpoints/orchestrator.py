"""
Entity-Perspective Orchestrators for the BBS-ISS protocol.

Each orchestrator wraps a single local Entity and holds Endpoint handles
to other participants. An orchestrator can only initiate interactions that
its entity supports.

Classes:
    Orchestrator           — Base class with shared endpoint management.
    HolderOrchestrator     — Drives issuance, re-issuance, and presentation-execution.
    IssuerOrchestrator     — Drives registry registration and updates.
    VerifierOrchestrator   — Drives presentation-announcement and verification.
    RegistryOrchestrator   — Thin wrapper for the passive Registry entity.
"""

import bbs_iss.interfaces.requests_api as api
from threading import Timer
from bbs_iss.entities.entity import Entity
from bbs_iss.endpoints.endpoint import Endpoint
from bbs_iss.endpoints.trail import RequestTrail

# ─── Type aliases ────────────────────────────────────────────────────────────

from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance


# ═══════════════════════════════════════════════════════════════════════════════
# Base Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class Orchestrator:
    """
    Base class for entity-perspective orchestrators.

    Holds a local Entity and a dictionary of Endpoint handles
    to other protocol participants.
    """

    def __init__(self, entity: Entity, **endpoints: Endpoint):
        """
        Parameters
        ----------
        entity : Entity
            The local entity this orchestrator manages.
        **endpoints : Endpoint
            Named endpoint handles, e.g. issuer=..., registry=...
        """
        self.entity = entity
        self.endpoints = endpoints

    def _get_endpoint(self, name: str) -> Endpoint:
        """Retrieve a named endpoint, raising if not configured."""
        ep = self.endpoints.get(name)
        if ep is None:
            raise ValueError(f"Endpoint '{name}' not configured on this orchestrator")
        return ep


# ═══════════════════════════════════════════════════════════════════════════════
# HolderOrchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class HolderOrchestrator(Orchestrator):
    """
    Interaction interface for a Holder entity.

    Drives issuance, re-issuance, and presentation-execution flows.
    The Holder is always the local entity; Issuer, Verifier, and
    Registry are accessed through Endpoints.
    """

    def __init__(self, entity: HolderInstance, **endpoints: Endpoint):
        super().__init__(entity, **endpoints)
        self.pending_requests: list[api.VPRequest] = []

    def get_pending_requests(self) -> list[api.VPRequest]:
        """Return all queued VPRequests awaiting user consent."""
        return list(self.pending_requests)

    # ── Flow A: Credential Issuance ──────────────────────────────────────

    def execute_issuance(
        self,
        issuer_name: str,
        attributes: api.IssuanceAttributes,
        cred_name: str,
    ) -> RequestTrail:
        """
        Execute the 4-step blind issuance protocol.

        Handles registry resolution on cache miss and error responses
        at every step.

        Parameters
        ----------
        issuer_name : str
            Name of the target issuer (must be resolvable via registry).
        attributes : IssuanceAttributes
            The credential attributes (revealed + hidden).
        cred_name : str
            Name under which the credential will be stored.

        Returns
        -------
        RequestTrail
            Execution trail with status COMPLETED or FAILED.
        """
        trail = RequestTrail(protocol="ISSUANCE")
        issuer_ep = self._get_endpoint("issuer")
        registry_ep = self._get_endpoint("registry")

        try:
            # Step 1: Holder initiates issuance
            result = self.entity.issuance_request(issuer_name, attributes, cred_name)
            trail.record("Holder", "Issuer", result)

            # Handle registry resolution on cache miss
            if isinstance(result, api.GetIssuerDetailsRequest):
                trail.record("Holder", "Registry", result)
                registry_resp = registry_ep.exchange(result)
                trail.record("Registry", "Holder", registry_resp)

                result = self.entity.process_request(registry_resp)
                trail.record("Holder", "Issuer", result)

                if isinstance(result, api.ErrorResponse):
                    trail.mark_failed(result)
                    return trail

            # Step 2: Forward issuance request to Issuer → get Freshness
            freshness = issuer_ep.exchange(result)
            trail.record("Issuer", "Holder", freshness)

            if isinstance(freshness, api.ErrorResponse):
                self.entity.process_request(freshness)
                trail.mark_failed(freshness)
                return trail

            # Step 3: Holder processes freshness → BlindSignRequest
            blind_req = self.entity.process_request(freshness)
            trail.record("Holder", "Issuer", blind_req)

            # Step 4: Forward BlindSignRequest to Issuer → get ForwardVC
            forward_vc = issuer_ep.exchange(blind_req)
            trail.record("Issuer", "Holder", forward_vc)

            if isinstance(forward_vc, api.ErrorResponse):
                self.entity.process_request(forward_vc)
                trail.mark_failed(forward_vc)
                return trail

            # Step 5: Holder processes VC (unblind, verify, save)
            self.entity.process_request(forward_vc)
            trail.mark_completed()

        except Exception as e:
            self.entity.reset()
            trail.mark_exception(e)

        return trail

    # ── Flow C: Credential Re-issuance ───────────────────────────────────

    def execute_re_issuance(
        self,
        vc_name: str,
        always_hidden_keys: list[str] = None,
    ) -> RequestTrail:
        """
        Execute the credential re-issuance protocol.

        Combines proof of possession (VP) with a new blinded commitment
        to renew an expiring credential.

        Parameters
        ----------
        vc_name : str
            Name of the stored credential to renew.
        always_hidden_keys : list[str], optional
            Keys that must never be revealed (e.g. link secret).

        Returns
        -------
        RequestTrail
            Execution trail with status COMPLETED or FAILED.
        """
        trail = RequestTrail(protocol="RE_ISSUANCE")
        issuer_ep = self._get_endpoint("issuer")

        try:
            # Step 1: Holder initiates re-issuance
            reiss_req = self.entity.re_issuance_request(vc_name, always_hidden_keys)
            trail.record("Holder", "Issuer", reiss_req)

            # Step 2: Forward to Issuer → get Freshness
            freshness = issuer_ep.exchange(reiss_req)
            trail.record("Issuer", "Holder", freshness)

            if isinstance(freshness, api.ErrorResponse):
                self.entity.process_request(freshness)
                trail.mark_failed(freshness)
                return trail

            # Step 3: Holder processes freshness → ForwardVpAndCmtRequest
            vp_cmt_req = self.entity.process_request(freshness)
            trail.record("Holder", "Issuer", vp_cmt_req)

            # Step 4: Forward VP+Commitment to Issuer → get ForwardVC
            forward_vc = issuer_ep.exchange(vp_cmt_req)
            trail.record("Issuer", "Holder", forward_vc)

            if isinstance(forward_vc, api.ErrorResponse):
                self.entity.process_request(forward_vc)
                trail.mark_failed(forward_vc)
                return trail

            # Step 5: Holder processes VC (unblind, verify, save)
            self.entity.process_request(forward_vc)
            trail.mark_completed()

        except Exception as e:
            self.entity.reset()
            trail.mark_exception(e)

        return trail

    # ── Flow B (Holder's half): Presentation-Execution ───────────────────

    def execute_presentation(
        self,
        vp_request: api.VPRequest,
        vc_name: str,
        always_hidden_keys: list[str] = None,
    ) -> tuple[RequestTrail, api.ForwardVPResponse]:
        """
        Execute the Holder's half of the presentation protocol.

        This is called after the Holder has reviewed the Verifier's
        VPRequest and given consent to disclose the requested attributes.

        Builds the VP, auto-sends it to the Verifier endpoint if
        configured, and removes the request from the pending queue.

        Parameters
        ----------
        vp_request : VPRequest
            The Verifier's presentation request.
        vc_name : str
            Name of the stored credential to present.
        always_hidden_keys : list[str], optional
            Keys that must never be revealed.

        Returns
        -------
        tuple[RequestTrail, ForwardVPResponse]
            (trail, forward_vp_response). forward_vp_response is None
            if the protocol failed.
        """
        trail = RequestTrail(protocol="PRESENTATION_EXECUTION")
        forward_vp = None

        try:
            # Build VP
            forward_vp = self.entity.present_credential(
                vp_request, vc_name, always_hidden_keys
            )
            trail.record("Holder", "Verifier", forward_vp)

            # Auto-send to Verifier if endpoint is configured
            if "verifier" in self.endpoints:
                self._get_endpoint("verifier").send(forward_vp)

            # Remove from pending queue if present
            if vp_request in self.pending_requests:
                self.pending_requests.remove(vp_request)

            trail.mark_completed()

        except Exception as e:
            self.entity.reset()
            trail.mark_exception(e)

        return trail, forward_vp

    # ── Registry sync ────────────────────────────────────────────────────

    def sync_registry(self) -> RequestTrail:
        """Bulk-fetch all issuer details from registry into local cache."""
        trail = RequestTrail(protocol="REGISTRY_SYNC")
        registry_ep = self._get_endpoint("registry")

        bulk_req = self.entity.fetch_all_issuer_details()
        trail.record("Holder", "Registry", bulk_req)

        bulk_resp = registry_ep.exchange(bulk_req)
        trail.record("Registry", "Holder", bulk_resp)

        self.entity.process_request(bulk_resp)
        trail.mark_completed()
        return trail


# ═══════════════════════════════════════════════════════════════════════════════
# VerifierOrchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class VerifierOrchestrator(Orchestrator):
    """
    Interaction interface for a Verifier entity.

    Drives presentation-announcement (generating a VPRequest) and
    presentation-completion (verifying a received VP). In networked mode,
    can also perform the full request-presentation flow via the Holder
    endpoint.
    """

    def __init__(self, entity: VerifierInstance, vp_timeout_seconds: int = None, **endpoints: Endpoint):
        super().__init__(entity, **endpoints)
        self.verification_results: list[tuple] = []
        self._vp_timeout_seconds = vp_timeout_seconds
        self._timeout_timer = None

    # ── Flow B: Send VP Request to Holder ─────────────────────────────

    def send_presentation_request(
        self,
        requested_attributes: list[str],
    ) -> tuple[RequestTrail, api.VPRequest]:
        """
        Generate a VPRequest and send it to the Holder endpoint.

        The Holder's listener will queue the request for user consent.
        The Verifier then waits for the ForwardVPResponse to arrive
        at its own listener.

        Parameters
        ----------
        requested_attributes : list[str]
            Attribute names the Verifier wants disclosed.

        Returns
        -------
        tuple[RequestTrail, VPRequest]
            (trail, vp_request)
        """
        trail = RequestTrail(protocol="PRESENTATION_REQUEST")
        vp_request = None

        try:
            vp_request = self.entity.presentation_request(requested_attributes)
            trail.record("Verifier", "Holder", vp_request)

            holder_ep = self._get_endpoint("holder")
            holder_ep.send(vp_request)

            self._start_timeout()
            trail.mark_completed()

        except Exception as e:
            self.entity.reset()
            trail.mark_exception(e)

        return trail, vp_request

    def _start_timeout(self):
        """Start a background timer that resets the Verifier state on expiry."""
        self._cancel_timeout()
        if self._vp_timeout_seconds is not None:
            self._timeout_timer = Timer(
                self._vp_timeout_seconds,
                self._on_timeout,
            )
            self._timeout_timer.daemon = True
            self._timeout_timer.start()

    def _cancel_timeout(self):
        """Cancel any running timeout timer."""
        if self._timeout_timer is not None:
            self._timeout_timer.cancel()
            self._timeout_timer = None

    def _on_timeout(self):
        """Called when the VP timeout expires. Resets the Verifier state."""
        self.entity.reset()
        self._timeout_timer = None

    # ── Flow B (Verifier's half): Presentation-Announcement ──────────────

    def announce_presentation(
        self,
        requested_attributes: list[str],
    ) -> api.VPRequest:
        """
        Generate a VPRequest for the specified attributes.

        The caller is responsible for delivering this to the Holder
        (either via endpoint or manual handoff in all-local mode).

        Parameters
        ----------
        requested_attributes : list[str]
            Attribute names the Verifier wants disclosed.

        Returns
        -------
        VPRequest
            The challenge request containing requested attributes and nonce.
        """
        vp_request = self.entity.presentation_request(requested_attributes)
        self._start_timeout()
        return vp_request

    # ── Flow B (Verifier's half): Complete Presentation ──────────────────

    def complete_presentation(
        self,
        forward_vp_response: api.ForwardVPResponse,
    ) -> tuple:
        """
        Verify a received ForwardVPResponse.

        Handles registry resolution if the Verifier has a cache miss
        for the issuer's public data.

        Parameters
        ----------
        forward_vp_response : ForwardVPResponse
            The VP response received from the Holder.

        Returns
        -------
        tuple[bool, dict | None, VerifiablePresentation]
            (is_valid, revealed_attributes, vp)
        """
        self._cancel_timeout()
        result = self.entity.process_request(forward_vp_response)

        # Handle registry resolution on cache miss
        if isinstance(result, api.GetIssuerDetailsRequest):
            registry_ep = self._get_endpoint("registry")
            registry_resp = registry_ep.exchange(result)
            result = self.entity.process_request(registry_resp)

        return result

    # ── Full presentation request via endpoint ───────────────────────────

    def request_presentation(
        self,
        requested_attributes: list[str],
    ) -> tuple[RequestTrail, tuple]:
        """
        Full presentation flow via the Holder endpoint.

        Generates a VPRequest, sends it to the Holder endpoint
        (which blocks until the Holder responds), and verifies
        the returned VP.

        Parameters
        ----------
        requested_attributes : list[str]
            Attribute names the Verifier wants disclosed.

        Returns
        -------
        tuple[RequestTrail, tuple]
            (trail, (is_valid, revealed_attributes, vp))
        """
        trail = RequestTrail(protocol="PRESENTATION_REQUEST")
        holder_ep = self._get_endpoint("holder")

        # Generate and send VPRequest
        vp_request = self.entity.presentation_request(requested_attributes)
        trail.record("Verifier", "Holder", vp_request)

        # Exchange: blocks until Holder responds with ForwardVPResponse
        forward_vp = holder_ep.exchange(vp_request)
        trail.record("Holder", "Verifier", forward_vp)

        # Verify
        result = self.entity.process_request(forward_vp)

        # Handle registry resolution on cache miss
        if isinstance(result, api.GetIssuerDetailsRequest):
            registry_ep = self._get_endpoint("registry")
            trail.record("Verifier", "Registry", result)
            registry_resp = registry_ep.exchange(result)
            trail.record("Registry", "Verifier", registry_resp)
            result = self.entity.process_request(registry_resp)

        trail.mark_completed()
        return trail, result

    # ── Registry sync ────────────────────────────────────────────────────

    def sync_registry(self) -> RequestTrail:
        """Bulk-fetch all issuer details from registry into local cache."""
        trail = RequestTrail(protocol="REGISTRY_SYNC")
        registry_ep = self._get_endpoint("registry")

        bulk_req = self.entity.fetch_all_issuer_details()
        trail.record("Verifier", "Registry", bulk_req)

        bulk_resp = registry_ep.exchange(bulk_req)
        trail.record("Registry", "Verifier", bulk_resp)

        self.entity.process_request(bulk_resp)
        trail.mark_completed()
        return trail


# ═══════════════════════════════════════════════════════════════════════════════
# IssuerOrchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class IssuerOrchestrator(Orchestrator):
    """
    Interaction interface for an Issuer entity.

    Drives registry registration and update flows. The Issuer is
    mostly reactive for issuance/re-issuance (handled by its listener),
    but initiates registry administrative operations.
    """

    def __init__(self, entity: IssuerInstance, **endpoints: Endpoint):
        super().__init__(entity, **endpoints)

    def register_with_registry(self) -> RequestTrail:
        """
        Register this Issuer's public data with the Registry.

        Returns
        -------
        RequestTrail
            Execution trail with status COMPLETED or FAILED.
        """
        trail = RequestTrail(protocol="REGISTRY_REGISTRATION")
        registry_ep = self._get_endpoint("registry")

        reg_req = self.entity.register_issuer()
        trail.record("Issuer", "Registry", reg_req)

        reg_resp = registry_ep.exchange(reg_req)
        trail.record("Registry", "Issuer", reg_resp)

        self.entity.process_request(reg_resp)
        trail.mark_completed()
        return trail

    def update_registry(self) -> RequestTrail:
        """
        Update this Issuer's public data on the Registry.

        Used after bitstring rotation or epoch configuration changes.

        Returns
        -------
        RequestTrail
            Execution trail with status COMPLETED or FAILED.
        """
        trail = RequestTrail(protocol="REGISTRY_UPDATE")
        registry_ep = self._get_endpoint("registry")

        upd_req = self.entity.update_issuer_details()
        trail.record("Issuer", "Registry", upd_req)

        upd_resp = registry_ep.exchange(upd_req)
        trail.record("Registry", "Issuer", upd_resp)

        self.entity.process_request(upd_resp)
        trail.mark_completed()
        return trail

    def get_configuration(self) -> str:
        """Proxy to the Issuer entity's configuration display."""
        return self.entity.get_configuration()

    def get_bitstring_status(self) -> str:
        """Proxy to the Issuer entity's bitstring status display."""
        return self.entity.get_bitstring_status()


# ═══════════════════════════════════════════════════════════════════════════════
# RegistryOrchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class RegistryOrchestrator(Orchestrator):
    """
    Interaction interface for a Registry entity.

    The Registry is purely reactive — it processes incoming requests
    via its listener. The orchestrator provides administrative
    inspection utilities.
    """

    def __init__(self, entity: RegistryInstance, **endpoints: Endpoint):
        super().__init__(entity, **endpoints)

    def get_status(self) -> str:
        """Return a formatted summary of all registered issuers."""
        return self.entity.get_status_string()
