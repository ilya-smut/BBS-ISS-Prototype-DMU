import bbs_iss
import ursa_bbs_signatures as bbs
import bbs_iss.interfaces.requests_api as api
from bbs_iss.interfaces.exceptions import IssuerNotAvailable, FreshnessValueError, HolderNotInInteraction, HolderStateError, ProofValidityError
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
        
        def start_interaction(self, issuer_pub_key: bytes, attributes: api.IssuanceAttributes, cred_name: str, original_request: api.RequestType):
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

    def __init__(self):
        self.state = self.State()
        self.credentials = {}

    def process_request(self, request: api.Request):
        if not self.state.awaiting:
            raise HolderNotInInteraction("No active interaction")
        if request.request_type == api.RequestType.FRESHNESS:
            if self.state.original_request == api.RequestType.ISSUANCE:
                return self.blind_sign_request(request.nonce)
            else:
                raise HolderStateError("Invalid holder state")
        elif request.request_type == api.RequestType.FORWARD_VC:
            return self.unblind_and_verify(request.vc)           
        else:
            raise ValueError("Invalid request type")
            
    def issuance_request(self, issuer_pub_key: bytes, attributes: api.IssuanceAttributes, cred_name: str):
        self.state.start_interaction(issuer_pub_key, attributes, cred_name, api.RequestType.ISSUANCE)
        request = api.VCIssuanceRequest()
        return request
    
    def blind_sign_request(self, freshness: bytes):
        if not (self.state.awaiting and self.state.original_request == api.RequestType.ISSUANCE and freshness):
            raise HolderStateError("Invalid holder state")
        self.state.add_freshness(freshness)
        self.state.attributes.build_commitment(self.state.freshness, self.state.issuer_pub_key)
        request = api.BlindSignRequest(self.state.attributes, self.state.freshness, self.state.issuer_pub_key)
        return request
    
    def unblind_and_verify(self, vc: VerifiableCredential):
        if not (self.state.awaiting and self.state.original_request == api.RequestType.ISSUANCE and self.state.freshness):
            raise HolderStateError("Invalid holder state")
        signature = vc.proof
        unblinded_signature = bbs.unblind_signature(bbs.UnblindSignatureRequest(
            blinded_signature=signature,
            blinding_factor=self.state.attributes.get_blinding_factor()
        ))
        validity_status = bbs.verify(bbs.VerifyRequest(
            key_pair=bbs.BlsKeyPair(public_key=self.state.issuer_pub_key.key),
            signature=unblinded_signature,
            messages=self.state.attributes.attributes_to_list()
        ))
        
        self.state.end_interaction()
        return validity_status

            
        
        
        