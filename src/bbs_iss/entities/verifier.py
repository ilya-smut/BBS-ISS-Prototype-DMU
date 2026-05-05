import ursa_bbs_signatures as bbs
import bbs_iss.interfaces.requests_api as api
from bbs_iss.utils.utils import gen_nonce
from bbs_iss.interfaces.credential import VerifiablePresentation
from bbs_iss.exceptions.exceptions import VerifierStateError, VerifierNotInInteraction

class VerifierInstance:
    class State:
        def __init__(self):
            self.awaiting = False
            self.freshness = None
            self.attributes = None
            self.type = None
        def start_vp_request(self, nonce: bytes, attributes: list[str]):
            self.freshness = nonce
            self.attributes = attributes
            self.awaiting = True
            self.type = api.RequestType.VP_REQUEST
        def end_interaction(self):
            self.freshness = None
            self.attributes = None
            self.awaiting = False
            self.type = None
        @property
        def available(self) -> bool:
            return not self.awaiting
    
    def __init__(self):
        self.state = self.State()

    def presentation_request(self, requested_attributes: list[str]):
        if not self.state.available:
            raise VerifierStateError("Verifier is not available", state=self.state)
        nonce = gen_nonce()
        self.state.start_vp_request(nonce, requested_attributes)
        return api.VPRequest(requested_attributes, nonce)

    def process_request(self, request: api.Request):
        if self.state.available:
            raise VerifierNotInInteraction("No active interaction")
        if request.request_type == api.RequestType.FORWARD_VP:
            return self.verify_vp(request.vp, request.pub_key)
        else:
            raise ValueError("Invalid request type")
        
    def verify_vp(self, vp: VerifiablePresentation, pub_key: api.PublicKeyBLS) -> tuple[bool, dict[str, str] | None, VerifiablePresentation]:
        """
        Verifies a Verifiable Presentation against the challenge nonce
        held in state and the issuer's public key.

        Verification is two-phase:
            1. **Attribute completeness** — the VP's credentialSubject must
               contain every attribute the Verifier originally requested.
            2. **Cryptographic validity** — the BBS+ ZKP must verify against
               the issuer's public key and the bound nonce.

        Parameters
        ----------
        vp : VerifiablePresentation
            The presentation to verify.
        pub_key : PublicKeyBLS
            The issuer's BLS12-381 G2 public key.

        Returns
        -------
        tuple[bool, dict[str, str] | None, VerifiablePresentation]
            (is_valid, revealed_attributes, vp)
            On failure, revealed_attributes is None.
        """
        # ── Phase 1: Attribute completeness ──────────────────────────
        received_keys = set(vp.verifiableCredential["credentialSubject"].keys())
        requested_keys = set(self.state.attributes)
        missing = requested_keys - received_keys
        if missing:
            self.state.end_interaction()
            return (False, None, vp)

        # ── Phase 2: Cryptographic verification ──────────────────────
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