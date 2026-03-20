from enum import Enum
import os
import ursa_bbs_signatures as bbs
from bbs_iss.interfaces.requests_api import api
from bbs_iss.interfaces.exceptions import IssuerNotAvailable, FreshnessValueError

class IssuerInstance:
    
    class State:
        def __init__(self):
            self.available = True
            self.freshness = None
            self.type = None
        def start_interaction(self, type: api.RequestType, nonce):
            self.freshness = nonce
            self.available = False
            self.type = type
        def end_interaction(self):
            self.freshness = None
            self.available = True
            self.type = None
    
    def __init__(self, _private_key_pair: bbs.BlsKeyPair = None):
        self.state = self.State()
        if _private_key_pair is None:
            self._private_key_pair = self.key_gen()
            self.public_key = api.PublicKeyBLS(self._private_key_pair.public_key)
        else:
            self._private_key_pair = _private_key_pair
            self.public_key = api.PublicKeyBLS(self._private_key_pair.public_key)


    @staticmethod
    def gen_nonce():
        return os.urandom(32)   


    def process_request(self, request: api.Request):
        if request.request_type == api.RequestType.ISSUANCE:
            if not self.state.available:
                raise IssuerNotAvailable()
            nonce = self.gen_nonce()
            self.state.start_interaction(api.RequestType.ISSUANCE, nonce)
            return nonce
        if request.request_type == api.RequestType.BLIND_SIGN:
            blind_signature = self.blind_sign(request)
            self.state.end_interaction()
            return blind_signature


    def blind_sign(self, request: api.BlindSignRequest):
        ver_commitment_req = bbs.VerifyBlindedCommitmentRequest(
            public_key=api.SigningPublicKey.derive_signing_public_key(self.public_key, request.total_messages).key,
            proof = request.proof,
            blinded_indices=request.blinded_indices,
            nonce = self.state.freshness
        )
        if bbs.verify_blinded_commitment(ver_commitment_req) != bbs.SignatureProofStatus.success:
            self.state.end_interaction()
            raise FreshnessValueError()

        ursa_Blind_sign_request = bbs.BlindSignRequest(
            secret_key=self._private_key_pair,
            public_key=api.SigningPublicKey.derive_signing_public_key(self.public_key, request.total_messages).key,
            commitment=request.commitment,
            messages=request.revealed_attributes
        )
        blinded_signature = bbs.blind_sign(ursa_Blind_sign_request)
        return blinded_signature


    def generate_vc(self):
        pass
    
    
    def key_gen(self):
        return bbs.BlsKeyPair.generate_g2(seed = os.urandom(32))