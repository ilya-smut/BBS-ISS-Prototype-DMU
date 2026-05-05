import bbs_iss
import ursa_bbs_signatures as bbs
import bbs_iss.interfaces.requests_api as api
from bbs_iss.exceptions.exceptions import IssuerNotAvailable, FreshnessValueError, HolderNotInInteraction, HolderStateError, ProofValidityError
from bbs_iss.interfaces.credential import VerifiableCredential


class HolderInstance:

    class State:
        def __init__(self, awaiting: bool = False, freshness: bytes = None, issuer_pub_key: api.PublicKeyBLS = None, attributes: api.IssuanceAttributes = None, cred_name: str = None, original_request: api.RequestType = None):
            self.awaiting = awaiting
            self.freshness = freshness
            self.issuer_pub_key = issuer_pub_key
            self.attributes = attributes
            self.cred_name = cred_name
            self.original_request = original_request
        
        def start_issuance_interaction(self, issuer_pub_key: bytes, attributes: api.IssuanceAttributes, cred_name: str, original_request: api.RequestType):
            self.awaiting = True
            self.issuer_pub_key = issuer_pub_key
            self.attributes = attributes
            self.cred_name = cred_name
            self.original_request = original_request

        def add_freshness(self, nonce):
            self.freshness = nonce
        
        def end_interaction(self):
            self.awaiting = False
            self.freshness = None
            self.issuer_pub_key = None
            self.attributes = None
            self.cred_name = None
            self.original_request = None

        @property
        def blind_sign_request_ready(self) -> bool:
            return (self.awaiting and self.original_request == api.RequestType.ISSUANCE and (not bool(self.freshness)))

        @property
        def unblind_ready(self) -> bool:
            return (self.awaiting and self.original_request == api.RequestType.ISSUANCE and bool(self.freshness))

    def __init__(self):
        self.state = self.State()
        self.credentials = {}
    

    def process_request(self, request: api.Request):
        if not self.state.awaiting:
            raise HolderNotInInteraction("No active interaction")
        if request.request_type == api.RequestType.FRESHNESS:
            return self.blind_sign_request(request.nonce)
        elif request.request_type == api.RequestType.FORWARD_VC:
            return self.unblind_verify_save_vc(request.vc)           
        else:
            raise ValueError("Invalid request type")
            
    def issuance_request(self, issuer_pub_key: bytes, attributes: api.IssuanceAttributes, cred_name: str):
        self.state.start_issuance_interaction(issuer_pub_key, attributes, cred_name, api.RequestType.ISSUANCE)
        request = api.VCIssuanceRequest()
        return request
    
    def blind_sign_request(self, freshness: bytes):
        if not self.state.blind_sign_request_ready:
            raise HolderStateError("Invalid holder state", state=self.state)
        self.state.add_freshness(freshness)
        self.state.attributes.build_commitment_append_meta(self.state.freshness, self.state.issuer_pub_key)
        request = api.BlindSignRequest(self.state.attributes)
        return request
    
    def verify_vc(self, pub_key: api.PublicKeyBLS, vc: VerifiableCredential = None, vc_name: str = None):
        if vc and not vc_name:
            validity_status = bbs.verify(vc.prepare_verification_request(pub_key))
        elif vc_name and not vc:
            vc = self.credentials[vc_name]
            validity_status = bbs.verify(vc.prepare_verification_request(pub_key))
        else:
            raise ValueError("Invalid arguments")
        return validity_status
        
    
    def unblind_verify_save_vc(self, vc: VerifiableCredential):
        if not self.state.unblind_ready:
            raise HolderStateError("Invalid holder state", state=self.state)
        blind_signature = vc.proof
        unblinded_signature = bbs.unblind_signature(bbs.UnblindSignatureRequest(
            blinded_signature=blind_signature,
            blinding_factor=self.state.attributes.get_blinding_factor()
        ))
        
        # Updating VC
        vc.proof = unblinded_signature
        for attribute in self.state.attributes.blinded_attributes:
            vc.credential_subject[attribute.key] = attribute.message
        # Verifying unblinded VC
        validity_status = self.verify_vc(pub_key=self.state.issuer_pub_key, vc=vc)
        if not validity_status:
            self.state.end_interaction()
            raise ProofValidityError("Invalid proof")

        # Saving VC
        self.credentials[self.state.cred_name] = vc
        
        self.state.end_interaction()
        return validity_status

            
        
        
        