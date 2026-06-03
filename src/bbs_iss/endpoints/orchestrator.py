

import bbs_iss.interfaces.requests_api as api
from threading import Timer
from bbs_iss.entities.entity import Entity
from bbs_iss.endpoints.endpoint import Endpoint
from bbs_iss.endpoints.trail import RequestTrail



from bbs_iss.entities.holder import HolderInstance
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.verifier import VerifierInstance
from bbs_iss.entities.registry import RegistryInstance




class Orchestrator:

    def __init__(self, entity: Entity, **endpoints: Endpoint):
        self.entity = entity
        self.endpoints = endpoints

    def _get_endpoint(self, name: str) -> Endpoint:
        ep = self.endpoints.get(name)
        if ep is None:
            raise ValueError(f"Endpoint '{name}' not configured on this orchestrator")
        return ep




class HolderOrchestrator(Orchestrator):

    def __init__(self, entity: HolderInstance, **endpoints: Endpoint):
        super().__init__(entity, **endpoints)
        self.pending_requests: list[api.VPRequest] = []

    def get_pending_requests(self) -> list[api.VPRequest]:
        return list(self.pending_requests)

    def execute_issuance(
        self,
        issuer_name: str,
        attributes: api.IssuanceAttributes,
        cred_name: str,
    ) -> RequestTrail:
        """Execute the 4-step blind issuance protocol."""
        trail = RequestTrail(protocol="ISSUANCE")
        issuer_ep = self._get_endpoint("issuer")
        registry_ep = self._get_endpoint("registry")

        try:
            # Holder initiates issuance
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

            # Forward issuance request to Issuer → get Freshness
            freshness = issuer_ep.exchange(result)
            trail.record("Issuer", "Holder", freshness)

            if isinstance(freshness, api.ErrorResponse):
                self.entity.process_request(freshness)
                trail.mark_failed(freshness)
                return trail

            # Holder processes freshness → BlindSignRequest
            blind_req = self.entity.process_request(freshness)
            trail.record("Holder", "Issuer", blind_req)

            # Forward BlindSignRequest to Issuer → get ForwardVC
            forward_vc = issuer_ep.exchange(blind_req)
            trail.record("Issuer", "Holder", forward_vc)

            if isinstance(forward_vc, api.ErrorResponse):
                self.entity.process_request(forward_vc)
                trail.mark_failed(forward_vc)
                return trail

            # Holder processes VC (unblind, verify, save)
            self.entity.process_request(forward_vc)
            trail.mark_completed()

        except Exception as e:
            self.entity.reset()
            trail.mark_exception(e)

        return trail

    def execute_re_issuance(
        self,
        vc_name: str,
        always_hidden_keys: list[str] = None,
    ) -> RequestTrail:
        """Execute the credential re-issuance protocol."""
        trail = RequestTrail(protocol="RE_ISSUANCE")
        issuer_ep = self._get_endpoint("issuer")

        try:
            # Holder initiates re-issuance
            reiss_req = self.entity.re_issuance_request(vc_name, always_hidden_keys)
            trail.record("Holder", "Issuer", reiss_req)

            # Forward to Issuer → get Freshness
            freshness = issuer_ep.exchange(reiss_req)
            trail.record("Issuer", "Holder", freshness)

            if isinstance(freshness, api.ErrorResponse):
                self.entity.process_request(freshness)
                trail.mark_failed(freshness)
                return trail

            # Holder processes freshness → ForwardVpAndCmtRequest
            vp_cmt_req = self.entity.process_request(freshness)
            trail.record("Holder", "Issuer", vp_cmt_req)

            # Forward VP+Commitment to Issuer → get ForwardVC
            forward_vc = issuer_ep.exchange(vp_cmt_req)
            trail.record("Issuer", "Holder", forward_vc)

            if isinstance(forward_vc, api.ErrorResponse):
                self.entity.process_request(forward_vc)
                trail.mark_failed(forward_vc)
                return trail

            # Holder processes VC (unblind, verify, save)
            self.entity.process_request(forward_vc)
            trail.mark_completed()

        except Exception as e:
            self.entity.reset()
            trail.mark_exception(e)

        return trail

    def execute_presentation(
        self,
        vp_request: api.VPRequest,
        vc_name: str,
        always_hidden_keys: list[str] = None,
    ) -> tuple[RequestTrail, api.ForwardVPResponse]:
        """Build a VP from the given request and auto-send to Verifier if configured."""
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

    def sync_registry(self) -> RequestTrail:
        trail = RequestTrail(protocol="REGISTRY_SYNC")
        registry_ep = self._get_endpoint("registry")

        bulk_req = self.entity.fetch_all_issuer_details()
        trail.record("Holder", "Registry", bulk_req)

        bulk_resp = registry_ep.exchange(bulk_req)
        trail.record("Registry", "Holder", bulk_resp)

        self.entity.process_request(bulk_resp)
        trail.mark_completed()
        return trail




class VerifierOrchestrator(Orchestrator):

    def __init__(self, entity: VerifierInstance, vp_timeout_seconds: int = None, **endpoints: Endpoint):
        super().__init__(entity, **endpoints)
        self.verification_results: list[tuple] = []
        self._vp_timeout_seconds = vp_timeout_seconds
        self._timeout_timer = None

    def send_presentation_request(
        self,
        requested_attributes: list[str],
    ) -> tuple[RequestTrail, api.VPRequest]:
        """Generate a VPRequest and send it to the Holder endpoint."""
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
        self._cancel_timeout()
        if self._vp_timeout_seconds is not None:
            self._timeout_timer = Timer(
                self._vp_timeout_seconds,
                self._on_timeout,
            )
            self._timeout_timer.daemon = True
            self._timeout_timer.start()

    def _cancel_timeout(self):
        if self._timeout_timer is not None:
            self._timeout_timer.cancel()
            self._timeout_timer = None

    def _on_timeout(self):
        self.entity.reset()
        self._timeout_timer = None

    def announce_presentation(
        self,
        requested_attributes: list[str],
    ) -> api.VPRequest:
        vp_request = self.entity.presentation_request(requested_attributes)
        self._start_timeout()
        return vp_request

    def complete_presentation(
        self,
        forward_vp_response: api.ForwardVPResponse,
    ) -> tuple:
        """Verify a received ForwardVPResponse, resolving issuer data from registry if needed."""
        self._cancel_timeout()
        result = self.entity.process_request(forward_vp_response)

        # Handle registry resolution on cache miss
        if isinstance(result, api.GetIssuerDetailsRequest):
            registry_ep = self._get_endpoint("registry")
            registry_resp = registry_ep.exchange(result)
            result = self.entity.process_request(registry_resp)

        return result

    def request_presentation(
        self,
        requested_attributes: list[str],
    ) -> tuple[RequestTrail, tuple]:
        """Full presentation flow: generate VPRequest, send to Holder, verify response."""
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

    def sync_registry(self) -> RequestTrail:
        trail = RequestTrail(protocol="REGISTRY_SYNC")
        registry_ep = self._get_endpoint("registry")

        bulk_req = self.entity.fetch_all_issuer_details()
        trail.record("Verifier", "Registry", bulk_req)

        bulk_resp = registry_ep.exchange(bulk_req)
        trail.record("Registry", "Verifier", bulk_resp)

        self.entity.process_request(bulk_resp)
        trail.mark_completed()
        return trail




class IssuerOrchestrator(Orchestrator):

    def __init__(self, entity: IssuerInstance, **endpoints: Endpoint):
        super().__init__(entity, **endpoints)

    def register_with_registry(self) -> RequestTrail:
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
        return self.entity.get_configuration()

    def get_bitstring_status(self) -> str:
        return self.entity.get_bitstring_status()




class RegistryOrchestrator(Orchestrator):

    def __init__(self, entity: RegistryInstance, **endpoints: Endpoint):
        super().__init__(entity, **endpoints)

    def get_status(self) -> str:
        return self.entity.get_status_string()
