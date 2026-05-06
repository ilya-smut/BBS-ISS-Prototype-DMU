import os
import ursa_bbs_signatures as bbs
import bbs_iss.interfaces.requests_api as api
import bbs_iss.utils.utils as utils
from bbs_iss.exceptions.exceptions import IssuerNotAvailable, FreshnessValueError, ProofValidityError
from bbs_iss.interfaces.credential import VerifiableCredential
from datetime import datetime, timedelta, timezone

MOCK_ISSUER_PARAMETERS = {
    "issuer": "Mock-Issuer"
}

class IssuerInstance:
    DEFAULT_VALID_UNTIL_WEEKS = 7
    DEFAULT_RE_ISSUANCE_WINDOW_DAYS = 7
    
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
            
        @property
        def re_issuance_ready(self) -> bool:
            return (not self.available and self.type == api.RequestType.RE_ISSUANCE and self.freshness is not None)
    
    def __init__(self, _private_key_pair: bbs.BlsKeyPair = None):
        self.state = self.State()
        if _private_key_pair is None:
            self._private_key_pair = self.key_gen()
            self.public_key = api.PublicKeyBLS(self._private_key_pair.public_key)
        else:
            self._private_key_pair = _private_key_pair
            self.public_key = api.PublicKeyBLS(self._private_key_pair.public_key) 
        self.valid_until_weeks = None
        self.re_issuance_window_days = None
        self.issuer_parameters = None

    def set_valid_until_weeks(self, weeks: int):
        self.valid_until_weeks = weeks
        
    def set_re_issuance_window_days(self, days: int):
        self.re_issuance_window_days = days
        
    def set_issuer_parameters(self, params: dict):
        self.issuer_parameters = params

    def get_configuration(self) -> str:
        current_params = self.issuer_parameters if self.issuer_parameters else MOCK_ISSUER_PARAMETERS
        current_valid_until = self.valid_until_weeks if self.valid_until_weeks is not None else self.DEFAULT_VALID_UNTIL_WEEKS
        current_window = self.re_issuance_window_days if self.re_issuance_window_days is not None else self.DEFAULT_RE_ISSUANCE_WINDOW_DAYS
        
        config = [
            "--- Issuer Configuration ---",
            f"Parameters: {current_params}",
            f"Public Key (hex): {self.public_key.key.hex()}",
            f"Valid Until (weeks): {current_valid_until}",
            f"Re-issuance Window (days): {current_window}",
            "----------------------------"
        ]
        return "\n".join(config)


    def process_request(self, request: api.Request):
        if request.request_type == api.RequestType.ISSUANCE:
            if not self.state.available:
                raise IssuerNotAvailable()
            return self.freshness_response(api.RequestType.ISSUANCE)
        elif request.request_type == api.RequestType.RE_ISSUANCE:
            if not self.state.available:
                raise IssuerNotAvailable()
            return self.freshness_response(api.RequestType.RE_ISSUANCE)
        elif request.request_type == api.RequestType.BLIND_SIGN:
            if self.state.type != api.RequestType.ISSUANCE:
                raise ValueError("Invalid state for blind sign")
            try:
                return self.issue_vc_blind(request)
            except Exception as e:
                self.state.end_interaction()
                raise e
        elif request.request_type == api.RequestType.FORWARD_VP_AND_CMT:
            if not self.state.re_issuance_ready:
                raise ValueError("Invalid state for re-issuance")
            try:
                return self.re_issue_vc(request)
            except Exception as e:
                self.state.end_interaction()
                raise e
        else:
            self.state.end_interaction()
            raise ValueError("Invalid request type")

    def blind_sign(self, request: api.BlindSignRequest):
        ver_commitment_req = bbs.VerifyBlindedCommitmentRequest(
            public_key=api.SigningPublicKey.derive_signing_public_key(self.public_key, request.total_messages).key,
            proof = request.proof,
            blinded_indices=request.messages_with_blinded_indices,
            nonce = self.state.freshness
        )
        if bbs.verify_blinded_commitment(ver_commitment_req) != bbs.SignatureProofStatus.success:
            self.state.end_interaction()
            raise ProofValidityError("Invalid proof of commitment to hidden attributes")

        ursa_Blind_sign_request = bbs.BlindSignRequest(
            secret_key=self._private_key_pair,
            public_key=api.SigningPublicKey.derive_signing_public_key(self.public_key, request.total_messages).key,
            commitment=request.commitment,
            messages=request.revealed_attributes
        )
        blinded_signature = bbs.blind_sign(ursa_Blind_sign_request)
        return blinded_signature


    def issue_vc_blind(self, request: api.BlindSignRequest):
        # Pre-computing VC
        attributes = VerifiableCredential.parse_sorted_keyed_indexed_messages(request.revealed_attributes+request.messages_with_blinded_indices)
        issuer_name = self.issuer_parameters["issuer"] if self.issuer_parameters and "issuer" in self.issuer_parameters else MOCK_ISSUER_PARAMETERS["issuer"]
        vc = VerifiableCredential(
            issuer=issuer_name,
            credential_subject=attributes,
            proof=None # VC is not signed yet
        )
        if vc.META_HASH_KEY not in vc.credential_subject:
            raise ValueError("META_HASH_KEY not found in credential subject")
            
        valid_until = self.generate_valid_until()
        revocation_material = self.generate_revocation_index()
        
        vc.credential_subject[vc.VALID_UNTIL_KEY] = valid_until
        vc.credential_subject[vc.REVOCATION_MATERIAL_KEY] = revocation_material
        
        for attr in request.revealed_attributes:
            if attr.key == vc.VALID_UNTIL_KEY:
                attr.message = valid_until
            elif attr.key == vc.REVOCATION_MATERIAL_KEY:
                attr.message = revocation_material

        meta_hash = vc.normalize_meta_fields() # Calculating metaHash
        vc.credential_subject[vc.META_HASH_KEY] = meta_hash # Appending metaHash to VC
        # Changing metaHash attribute in request
        # metaHash is always appended at the end, but we still iterate just in case. Starting from end for efficiency
        for attr in reversed(request.revealed_attributes):
            if attr.key == vc.META_HASH_KEY:
                attr.message = meta_hash
                break
        blind_signature = self.blind_sign(request)
        vc.proof = blind_signature
        
        forward_vc_response = api.ForwardVCResponse(vc=vc)
        self.state.end_interaction()
        return forward_vc_response
        
    def re_issue_vc(self, request: api.ForwardVpAndCmtRequest):
        # 1. Verify VP
        verification_request = request.vp.prepare_verification_request(
            pub_key=self.public_key,
            nonce=self.state.freshness,
            commitment=request.commitment
        )
        if not bbs.verify_proof(verification_request):
            self.state.end_interaction()
            raise ProofValidityError("Invalid VP proof")

        disclosed = request.vp.verifiableCredential["credentialSubject"]

        # 2. Compare attributes
        request_revealed = {attr.key: attr.message for attr in request.revealed_attributes}
        
        vp_keys = set(disclosed.keys())
        expected_keys = vp_keys - {VerifiableCredential.VALID_UNTIL_KEY, VerifiableCredential.REVOCATION_MATERIAL_KEY, VerifiableCredential.META_HASH_KEY}
        
        request_revealed_keys = set(request_revealed.keys()) - {VerifiableCredential.VALID_UNTIL_KEY, VerifiableCredential.REVOCATION_MATERIAL_KEY, VerifiableCredential.META_HASH_KEY}
        
        if expected_keys != request_revealed_keys:
            self.state.end_interaction()
            raise ValueError(f"Attribute keys mismatch between VP and blind sign request. Expected revealed: {expected_keys}, Provided revealed: {request_revealed_keys}")
            
        expected_total_messages = bbs.get_total_message_count(request.vp.verifiableCredential["proof"])
        if expected_total_messages != request.total_messages:
            self.state.end_interaction()
            raise ValueError("Total messages mismatch between VP and blind sign request")

        for k in request_revealed.keys():
            if k in expected_keys and request_revealed[k] != disclosed[k]:
                self.state.end_interaction()
                raise ValueError(f"Attribute value mismatch for key {k}")

        # 3. Expiration Check
        if VerifiableCredential.VALID_UNTIL_KEY not in disclosed:
            self.state.end_interaction()
            raise ValueError("Old credential does not have a validity period")
        
        old_expiry_str = disclosed[VerifiableCredential.VALID_UNTIL_KEY]
        old_expiry = datetime.fromisoformat(old_expiry_str.replace('Z', '+00:00'))
        
        window = self.re_issuance_window_days if self.re_issuance_window_days is not None else self.DEFAULT_RE_ISSUANCE_WINDOW_DAYS
        if old_expiry - datetime.now(timezone.utc) > timedelta(days=window):
            self.state.end_interaction()
            raise ValueError("Credential is not within the re-issuance window")

        # 4. Verify PoK
        ver_commitment_req = bbs.VerifyBlindedCommitmentRequest(
            public_key=api.SigningPublicKey.derive_signing_public_key(self.public_key, request.total_messages).key,
            proof=request.proof,
            blinded_indices=request.messages_with_blinded_indices,
            nonce=self.state.freshness
        )
        if bbs.verify_blinded_commitment(ver_commitment_req) != bbs.SignatureProofStatus.success:
            self.state.end_interaction()
            raise ProofValidityError("Invalid proof of commitment to hidden attributes")

        # 5. Revocation
        if VerifiableCredential.REVOCATION_MATERIAL_KEY in disclosed:
            self.revoke_index(disclosed[VerifiableCredential.REVOCATION_MATERIAL_KEY])

        # 6. Issue New VC
        attributes = VerifiableCredential.parse_sorted_keyed_indexed_messages(request.revealed_attributes + request.messages_with_blinded_indices)
        issuer_name = self.issuer_parameters["issuer"] if self.issuer_parameters and "issuer" in self.issuer_parameters else MOCK_ISSUER_PARAMETERS["issuer"]
        vc = VerifiableCredential(
            issuer=issuer_name,
            credential_subject=attributes,
            proof=None
        )
        
        valid_until = self.generate_valid_until(old_expiry=old_expiry)
        revocation_material = self.generate_revocation_index()
        
        vc.credential_subject[vc.VALID_UNTIL_KEY] = valid_until
        vc.credential_subject[vc.REVOCATION_MATERIAL_KEY] = revocation_material
        
        for attr in request.revealed_attributes:
            if attr.key == vc.VALID_UNTIL_KEY:
                attr.message = valid_until
            elif attr.key == vc.REVOCATION_MATERIAL_KEY:
                attr.message = revocation_material

        meta_hash = vc.normalize_meta_fields()
        vc.credential_subject[vc.META_HASH_KEY] = meta_hash
        
        for attr in reversed(request.revealed_attributes):
            if attr.key == vc.META_HASH_KEY:
                attr.message = meta_hash
                break

        ursa_Blind_sign_request = bbs.BlindSignRequest(
            secret_key=self._private_key_pair,
            public_key=api.SigningPublicKey.derive_signing_public_key(self.public_key, request.total_messages).key,
            commitment=request.commitment,
            messages=request.revealed_attributes
        )
        blind_signature = bbs.blind_sign(ursa_Blind_sign_request)
        vc.proof = blind_signature
        
        forward_vc_response = api.ForwardVCResponse(vc=vc)
        self.state.end_interaction()
        return forward_vc_response
    
    
    def key_gen(self):
        return bbs.BlsKeyPair.generate_g2(seed = os.urandom(32))

    def generate_valid_until(self, old_expiry: datetime = None) -> str:
        weeks = self.valid_until_weeks if self.valid_until_weeks is not None else self.DEFAULT_VALID_UNTIL_WEEKS
        epoch = timedelta(weeks=weeks)
        
        if old_expiry is None:
            expiry = datetime.now(timezone.utc) + epoch
        else:
            now = datetime.now(timezone.utc)
            distance = now - old_expiry
            if distance.total_seconds() < 0:
                expiry = old_expiry + epoch
            else:
                num_epochs = int(distance.total_seconds() // epoch.total_seconds())
                expiry = old_expiry + epoch * (num_epochs + 1)
                
        return expiry.isoformat(timespec='seconds').replace('+00:00', 'Z')

    def generate_revocation_index(self) -> str:
        return "123" # Mock implementation

    def revoke_index(self, index: str):
        # This method will be used in the future to mark the index as revoked in the revocation list.
        pass

    def freshness_response(self, request_type: api.RequestType):
        nonce = utils.gen_nonce()
        self.state.start_interaction(request_type, nonce)
        return api.FreshnessUpdateResponse(nonce)