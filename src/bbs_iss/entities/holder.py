import bbs_iss
import ursa_bbs_signatures as bbs
import bbs_iss.interfaces.requests_api as api
from bbs_iss.exceptions.exceptions import (
    IssuerNotAvailable, FreshnessValueError, HolderNotInInteraction, 
    HolderStateError, ProofValidityError, UnregisteredIssuerError
)
from bbs_iss.interfaces.credential import VerifiableCredential, VerifiablePresentation
from bbs_iss.utils.cache import PublicDataCache


class HolderInstance:

    class State:
        def __init__(self, awaiting: bool = False, freshness: bytes = None, issuer_pub_key: api.PublicKeyBLS = None, attributes: api.IssuanceAttributes = None, cred_name: str = None, original_request: api.RequestType = None, always_hidden_keys: list[str] = None):
            self.awaiting = awaiting
            self.freshness = freshness
            self.issuer_pub_key = issuer_pub_key
            self.attributes = attributes
            self.cred_name = cred_name
            self.original_request = original_request
            self.always_hidden_keys = always_hidden_keys
            self.pending_registry_request = None
            self.pending_issuer_name = None
        
        def start_issuance_interaction(self, issuer_pub_key: bytes, attributes: api.IssuanceAttributes, cred_name: str, original_request: api.RequestType):
            self.awaiting = True
            self.issuer_pub_key = issuer_pub_key
            self.attributes = attributes
            self.cred_name = cred_name
            self.original_request = original_request

        def start_re_issuance_interaction(self, issuer_pub_key: bytes, attributes: api.IssuanceAttributes, cred_name: str, always_hidden_keys: list[str] = None):
            self.awaiting = True
            self.issuer_pub_key = issuer_pub_key
            self.attributes = attributes
            self.cred_name = cred_name
            self.original_request = api.RequestType.RE_ISSUANCE
            self.always_hidden_keys = always_hidden_keys

        def add_freshness(self, nonce):
            self.freshness = nonce

        def start_registry_interaction(self, interaction_type: api.RequestType = api.RequestType.GET_ISSUER_DETAILS):
            self.awaiting = True
            self.pending_registry_request = interaction_type
        
        def end_interaction(self):
            self.awaiting = False
            self.freshness = None
            self.issuer_pub_key = None
            self.attributes = None
            self.cred_name = None
            self.original_request = None
            self.always_hidden_keys = None
            self.pending_registry_request = None
            self.pending_issuer_name = None

        @property
        def blind_sign_request_ready(self) -> bool:
            return (self.awaiting and self.original_request == api.RequestType.ISSUANCE and (not bool(self.freshness)))

        @property
        def unblind_ready(self) -> bool:
            return (self.awaiting and (self.original_request == api.RequestType.ISSUANCE or self.original_request == api.RequestType.RE_ISSUANCE) and bool(self.freshness))

        @property
        def forward_vp_and_cmt_ready(self) -> bool:
            return (self.awaiting and self.original_request == api.RequestType.RE_ISSUANCE and (not bool(self.freshness)))

        @property
        def registry_interaction_ready(self) -> bool:
            return self.awaiting and self.pending_registry_request in [api.RequestType.GET_ISSUER_DETAILS, api.RequestType.BULK_ISSUER_DETAILS_REQUEST]

    def __init__(self):
        self.state = self.State()
        self.credentials = {}
        self.public_data_cache = PublicDataCache()
    
    @property
    def available(self) -> bool:
        """Returns True if the Holder is not currently in an active interaction."""
        return not self.state.awaiting

    def reset(self):
        """Manually resets the Holder state, cancelling any active interaction."""
        self.state.end_interaction()
    

    def process_request(self, request: api.Request):
        if not self.state.awaiting:
            raise HolderNotInInteraction("No active interaction")
        if request.request_type == api.RequestType.FRESHNESS:
            if self.state.original_request == api.RequestType.ISSUANCE:
                return self.blind_sign_request(request.nonce)
            elif self.state.original_request == api.RequestType.RE_ISSUANCE:
                return self.forward_vp_and_cmt_request(request.nonce)
            else:
                raise ValueError("Invalid original request state")
        elif request.request_type == api.RequestType.FORWARD_VC:
            return self.unblind_verify_save_vc(request.vc)           
        elif request.request_type == api.RequestType.ISSUER_DETAILS_RESPONSE:
            if not self.state.registry_interaction_ready:
                self.state.end_interaction()
                raise HolderStateError("Invalid holder state for registry response", state=self.state)
            
            if request.issuer_data:
                self.public_data_cache.update(request.issuer_data.issuer_name, request.issuer_data)
            
            if self.state.pending_issuer_name:
                # Try to resolve again from updated cache
                issuer_name = self.state.pending_issuer_name
                self.state.pending_issuer_name = None # Clear it now
                
                details = self.public_data_cache.get(issuer_name)
                if details:
                    # Successful resolution - resume flow
                    self.state.issuer_pub_key = details.public_key
                    self.state.pending_registry_request = None
                    if self.state.original_request == api.RequestType.ISSUANCE:
                        return api.VCIssuanceRequest()
                    # Re-issuance is not currently supported via proactive resolution
                
                # If we are here, resolution failed or was not for issuance
                self.state.end_interaction()
                raise UnregisteredIssuerError(f"Issuer '{issuer_name}' not found in registry")

            self.state.end_interaction()
            return request.issuer_data
        elif request.request_type == api.RequestType.BULK_ISSUER_DETAILS_RESPONSE:
            if not self.state.registry_interaction_ready:
                self.state.end_interaction()
                raise HolderStateError("Invalid holder state for bulk registry response", state=self.state)
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
        """
        Retrieves issuer details from local cache or generates a registry request.
        """
        data = self.public_data_cache.get(issuer_name)
        if data:
            return data
            
        self.state.start_registry_interaction(api.RequestType.GET_ISSUER_DETAILS)
        return api.GetIssuerDetailsRequest(issuer_name)
            
    def fetch_all_issuer_details(self) -> api.BulkGetIssuerDetailsRequest:
        """
        Generates a bulk registry request to fetch all registered issuers.
        """
        self.state.start_registry_interaction(api.RequestType.BULK_ISSUER_DETAILS_REQUEST)
        return api.BulkGetIssuerDetailsRequest()
            
    def issuance_request(self, issuer_name: str, attributes: api.IssuanceAttributes, cred_name: str):
        details = self.get_issuer_details(issuer_name)
        
        if isinstance(details, api.IssuerPublicData):
            # Cache hit
            self.state.start_issuance_interaction(details.public_key, attributes, cred_name, api.RequestType.ISSUANCE)
            return api.VCIssuanceRequest()
        else:
            # Cache miss - details is a GetIssuerDetailsRequest
            self.state.pending_issuer_name = issuer_name
            self.state.attributes = attributes
            self.state.cred_name = cred_name
            self.state.original_request = api.RequestType.ISSUANCE
            return details

    def re_issuance_request(self, vc_name: str, always_hidden_keys: list[str] = None):
        if vc_name not in self.credentials:
            raise ValueError(f"Credential '{vc_name}' not found")
        stored_vc, stored_pub_key = self.credentials[vc_name]
        
        new_attributes = api.IssuanceAttributes()
        enforced_hidden = set()
        if always_hidden_keys:
            enforced_hidden.update(always_hidden_keys)
            
        for key, value in stored_vc.credential_subject.items():
            if key in [VerifiableCredential.VALID_UNTIL_KEY, VerifiableCredential.REVOCATION_MATERIAL_KEY, VerifiableCredential.META_HASH_KEY]:
                continue
            if key in enforced_hidden:
                new_attributes.append(key, value, api.AttributeType.HIDDEN)
            else:
                new_attributes.append(key, value, api.AttributeType.REVEALED)
                
        self.state.start_re_issuance_interaction(stored_pub_key, new_attributes, vc_name, always_hidden_keys)
        request = api.Request(api.RequestType.RE_ISSUANCE)
        return request

    def blind_sign_request(self, freshness: bytes):
        if not self.state.blind_sign_request_ready:
            raise HolderStateError("Invalid holder state", state=self.state)
        self.state.add_freshness(freshness)
        self.state.attributes.build_commitment_append_meta(self.state.freshness, self.state.issuer_pub_key)
        request = api.BlindSignRequest(self.state.attributes)
        return request
    
    def forward_vp_and_cmt_request(self, freshness: bytes):
        if not self.state.forward_vp_and_cmt_ready:
            raise HolderStateError("Invalid holder state", state=self.state)
        self.state.add_freshness(freshness)
        self.state.attributes.build_commitment_append_meta(self.state.freshness, self.state.issuer_pub_key)
        
        # Build VP
        stored_vc, _ = self.credentials[self.state.cred_name]
        
        enforced_hidden = set()
        if self.state.always_hidden_keys:
            enforced_hidden.update(self.state.always_hidden_keys)
            
        revealed_keys = [k for k in stored_vc.credential_subject.keys() if k not in enforced_hidden]
        
        vp = self.build_vp(
            revealed_keys=revealed_keys,
            nonce=freshness,
            vc_name=self.state.cred_name,
            always_hidden_keys=self.state.always_hidden_keys,
            commitment=self.state.attributes.get_commitment()
        )
        
        request = api.ForwardVpAndCmtRequest(vp, self.state.attributes)
        return request
    
    def verify_vc(self, pub_key: api.PublicKeyBLS = None, vc: VerifiableCredential = None, vc_name: str = None):
        if vc and not vc_name:
            if not pub_key:
                raise ValueError("pub_key is required when verifying a VC directly")
            validity_status = bbs.verify(vc.prepare_verification_request(pub_key))
        elif vc_name and not vc:
            stored_vc, stored_pub_key = self.credentials[vc_name]
            key = pub_key or stored_pub_key
            validity_status = bbs.verify(stored_vc.prepare_verification_request(key))
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

        # Saving VC alongside the issuer's public key
        self.credentials[self.state.cred_name] = (vc, self.state.issuer_pub_key)
        
        self.state.end_interaction()
        return validity_status


    def build_vp(
        self,
        revealed_keys: list[str],
        nonce: bytes,
        issuer_pub_key: api.PublicKeyBLS = None,
        vc: VerifiableCredential = None,
        vc_name: str = None,
        always_hidden_keys: list[str] = None,
        commitment: bytes = None,
    ) -> VerifiablePresentation:
        """
        Builds a Verifiable Presentation with a BBS+ zero-knowledge proof.

        Parameters
        ----------
        revealed_keys : list[str]
            Credential subject keys to disclose in the presentation.
        nonce : bytes
            The challenge nonce provided by the verifier.
        issuer_pub_key : PublicKeyBLS, optional
            The issuer's BLS12-381 G2 public key (needed to derive the
            BBS signing key for proof creation). If *vc_name* is used,
            the key is retrieved from storage automatically.
        vc : VerifiableCredential, optional
            The credential to present. Mutually exclusive with *vc_name*.
        vc_name : str, optional
            Name of a stored credential to present. Mutually exclusive with *vc*.
        always_hidden_keys : list[str], optional
            Application-level keys (e.g. link secret) that must never be
            revealed regardless of *revealed_keys*.
        commitment : bytes, optional
            The commitment to bind to the VP for re-issuance.

        Returns
        -------
        VerifiablePresentation
            A VP with the ZKP proof already populated.
        """
        # ── Resolve credential ───────────────────────────────────────
        if vc_name and not vc:
            stored_vc, stored_pub_key = self.credentials[vc_name]
            vc = stored_vc
            issuer_pub_key = issuer_pub_key or stored_pub_key
        elif not vc:
            raise ValueError("Either vc or vc_name must be provided")
        if not issuer_pub_key:
            raise ValueError("issuer_pub_key is required when presenting a VC directly")

        # Keys that are always hidden: caller-supplied
        enforced_hidden = set()
        if always_hidden_keys:
            enforced_hidden.update(always_hidden_keys)

        # ── Build VP shell (only revealed attributes) ────────────────
        vp = VerifiablePresentation()
        vp.from_verifiable_credential(vc, revealed_keys)

        # ── Prepare ProofMessage list ────────────────────────────────
        # The full message list from the VC (credential_subject already
        # includes metaHash from issuance) with each message tagged as
        # Revealed or Hidden.
        proof_messages = []
        for key, value in vc.credential_subject.items():
            if key in enforced_hidden or key not in revealed_keys:
                proof_messages.append(bbs.ProofMessage(
                    message=value,
                    proof_type=bbs.ProofMessageType.HiddenProofSpecificBlinding
                ))
            else:
                proof_messages.append(bbs.ProofMessage(
                    message=value,
                    proof_type=bbs.ProofMessageType.Revealed
                ))

        # ── Derive BBS signing public key ────────────────────────────
        total_messages = len(proof_messages)
        bls_key_pair = bbs.BlsKeyPair(public_key=issuer_pub_key.key)
        bbs_public_key = bls_key_pair.get_bbs_key(total_messages)

        # ── Build bound nonce and create proof ───────────────────────
        bound_nonce = vp.build_bound_nonce(nonce, commitment=commitment)

        proof_request = bbs.CreateProofRequest(
            public_key=bbs_public_key,
            messages=proof_messages,
            signature=vc.proof,
            nonce=bound_nonce
        )
        proof = bbs.create_proof(proof_request)

        # ── Attach proof to VP and return ────────────────────────────
        vp.add_proof(proof)
        return vp


    def present_credential(
        self,
        vp_request: api.VPRequest,
        vc_name: str,
        always_hidden_keys: list[str] = None,
    ) -> api.ForwardVPResponse:
        """
        Processes a Verifier's VP request and builds a Verifiable Presentation.

        Calling this method implies holder consent. Attribute selection
        and user approval are delegated to the application layer above.

        Checks performed:
            1. Credential exists in the holder's store.
            2. All requested attributes exist in the credential.
            3. No requested attribute conflicts with enforced-hidden keys.

        Parameters
        ----------
        vp_request : VPRequest
            The verifier's presentation request (contains requested
            attributes and challenge nonce).
        vc_name : str
            Name of the stored credential to present.
        always_hidden_keys : list[str], optional
            Keys that must never be revealed (e.g. link secret).

        Returns
        -------
        ForwardVPResponse
            Ready-to-send response containing the VP and the issuer's
            public key for the verifier.
        """
        # ── 1. Resolve credential ────────────────────────────────────
        if vc_name not in self.credentials:
            raise ValueError(f"Credential '{vc_name}' not found")
        stored_vc, stored_pub_key = self.credentials[vc_name]

        requested = set(vp_request.requested_attributes)

        # ── 2. Attribute availability ────────────────────────────────
        available = set(stored_vc.credential_subject.keys())
        missing = requested - available
        if missing:
            raise ValueError(
                f"Credential '{vc_name}' is missing requested attributes: {missing}"
            )

        # ── 3. Hidden-key conflict ───────────────────────────────────
        enforced_hidden = {VerifiableCredential.META_HASH_KEY}
        if always_hidden_keys:
            enforced_hidden.update(always_hidden_keys)
        conflict = requested & enforced_hidden
        if conflict:
            raise ValueError(
                f"Requested attributes conflict with enforced-hidden keys: {conflict}"
            )

        # ── 4. Build VP ──────────────────────────────────────────────
        vp = self.build_vp(
            revealed_keys=list(requested),
            nonce=vp_request.nonce,
            vc_name=vc_name,
            always_hidden_keys=always_hidden_keys,
        )

        return api.ForwardVPResponse(vp=vp, pub_key=stored_pub_key)