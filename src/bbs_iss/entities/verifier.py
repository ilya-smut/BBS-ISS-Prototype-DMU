import ursa_bbs_signatures as bbs
import bbs_iss.interfaces.requests_api as api
from bbs_iss.utils.utils import gen_nonce
from datetime import datetime, timezone
from bbs_iss.entities.entity import Entity
from bbs_iss.interfaces.credential import VerifiablePresentation, VerifiableCredential
from bbs_iss.exceptions.exceptions import VerifierStateError, VerifierNotInInteraction, MissingAttributeError
from bbs_iss.utils.cache import PublicDataCache

class VerifierInstance(Entity):
    class State:
        def __init__(self):
            self.awaiting = False
            self.freshness = None
            self.attributes = None
            self.type = None
            self.queued_response = None
        def start_vp_request(self, nonce: bytes, attributes: list[str]):
            self.freshness = nonce
            self.attributes = attributes
            self.awaiting = True
            self.type = api.RequestType.VP_REQUEST
        def start_registry_interaction(self, interaction_type: api.RequestType = api.RequestType.GET_ISSUER_DETAILS):
            self.awaiting = True
            self.type = interaction_type
        def end_interaction(self):
            self.freshness = None
            self.attributes = None
            self.awaiting = False
            self.type = None
            self.queued_response = None
        @property
        def available(self) -> bool:
            return not self.awaiting
        @property
        def registry_interaction_ready(self) -> bool:
            return self.awaiting and self.type in [api.RequestType.GET_ISSUER_DETAILS, api.RequestType.BULK_ISSUER_DETAILS_REQUEST]
    
    def __init__(self):
        self.state = self.State()
        self.public_data_cache = PublicDataCache()

    @property
    def available(self) -> bool:
        return self.state.available

    def reset(self):
        self.state.end_interaction()

    def presentation_request(self, requested_attributes: list[str]):
        if not self.state.available:
            raise VerifierStateError("Verifier is not available", state=self.state)
        nonce = gen_nonce()
        self.state.start_vp_request(nonce, requested_attributes)
        return api.VPRequest(requested_attributes, nonce)

    def process_request(self, request: api.Request):
        if self.state.available:
            raise VerifierNotInInteraction("No active interaction")
        elif request.request_type == api.RequestType.FORWARD_VP:
            issuer_name = request.vp.verifiableCredential["issuer"]
            details = self.get_issuer_details(issuer_name)
            
            if isinstance(details, api.IssuerPublicData):
                # We have the details in cache
                if details.public_key == request.pub_key:
                    return self.verify_vp(request.vp, request.pub_key)
                else:
                    # Key mismatch - need to fetch latest from registry
                    self.state.queued_response = request
                    self.state.start_registry_interaction(api.RequestType.GET_ISSUER_DETAILS)
                    return api.GetIssuerDetailsRequest(issuer_name)
            else:
                # details is a GetIssuerDetailsRequest
                self.state.queued_response = request
                return details

        elif request.request_type == api.RequestType.ISSUER_DETAILS_RESPONSE:
            if not self.state.registry_interaction_ready:
                self.state.end_interaction()
                raise VerifierStateError("Invalid verifier state for registry response", state=self.state)
            
            if request.issuer_data:
                self.public_data_cache.update(request.issuer_data.issuer_name, request.issuer_data)
            
            if self.state.queued_response:
                queued_req = self.state.queued_response
                self.state.queued_response = None
                
                # Try to resolve key again from updated cache
                issuer_name = queued_req.vp.verifiableCredential["issuer"]
                data = self.public_data_cache.get(issuer_name)
                
                if data and data.public_key == queued_req.pub_key:
                    return self.verify_vp(queued_req.vp, queued_req.pub_key)
                else:
                    # Still can't resolve or key mismatch
                    self.state.end_interaction()
                    return (False, None, queued_req.vp)
            
            self.state.end_interaction()
            return request.issuer_data
        elif request.request_type == api.RequestType.BULK_ISSUER_DETAILS_RESPONSE:
            if not self.state.registry_interaction_ready:
                self.state.end_interaction()
                raise VerifierStateError("Invalid verifier state for bulk registry response", state=self.state)
            for data in request.issuers_data:
                self.public_data_cache.update(data.issuer_name, data)
            self.state.end_interaction()
            return request.issuers_data
        elif request.request_type == api.RequestType.ERROR:
            self.state.end_interaction()
            return request
        else:
            raise ValueError("Invalid request type")
            
    def get_issuer_details(self, issuer_name: str) -> api.IssuerPublicData | api.GetIssuerDetailsRequest:
        data = self.public_data_cache.get(issuer_name)
        if data:
            return data
            
        self.state.start_registry_interaction(api.RequestType.GET_ISSUER_DETAILS)
        return api.GetIssuerDetailsRequest(issuer_name)
            
    def fetch_all_issuer_details(self) -> api.BulkGetIssuerDetailsRequest:
        self.state.start_registry_interaction(api.RequestType.BULK_ISSUER_DETAILS_REQUEST)
        return api.BulkGetIssuerDetailsRequest()

    def check_validity(
        self, 
        vp: VerifiablePresentation, 
        current_date: datetime = None, 
        with_bit_index: bool = False
    ) -> bool:
        revealed = vp.verifiableCredential["credentialSubject"]
        
        # Expiration check
        if VerifiableCredential.VALID_UNTIL_KEY not in revealed:
            raise MissingAttributeError(f"Attribute '{VerifiableCredential.VALID_UNTIL_KEY}' not found in presentation")
            
        expiry_str = revealed[VerifiableCredential.VALID_UNTIL_KEY]
        try:
            # Handle 'Z' suffix for UTC
            expiry_date = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
        except ValueError:
            return False # Invalid date format
            
        check_date = current_date or datetime.now(timezone.utc)
        if check_date > expiry_date:
            return False

        # Revocation check
        if with_bit_index:
            if VerifiableCredential.REVOCATION_MATERIAL_KEY not in revealed:
                raise MissingAttributeError(f"Attribute '{VerifiableCredential.REVOCATION_MATERIAL_KEY}' not found in presentation")
                
            bit_index = revealed[VerifiableCredential.REVOCATION_MATERIAL_KEY]
            issuer_name = vp.verifiableCredential["issuer"]
            
            # This will raise IssuerNotFoundInCacheError if not present
            is_revoked = self.public_data_cache.check_bit_index(issuer_name, bit_index)
            if is_revoked:
                return False

        return True
        
    def verify_vp(self, vp: VerifiablePresentation, pub_key: api.PublicKeyBLS) -> tuple[bool, dict[str, str] | None, VerifiablePresentation]:
        # Attribute completeness
        received_keys = set(vp.verifiableCredential["credentialSubject"].keys())
        requested_keys = set(self.state.attributes)
        missing = requested_keys - received_keys
        if missing:
            self.state.end_interaction()
            return (False, None, vp)

        # Cryptographic verification
        request = vp.prepare_verification_request(
            pub_key=pub_key,
            nonce=self.state.freshness,
        )
        is_valid = bbs.verify_proof(request)

        self.state.end_interaction()

        if is_valid:
            revealed = dict(vp.verifiableCredential["credentialSubject"])
            return (True, revealed, vp)
        return (False, None, vp)