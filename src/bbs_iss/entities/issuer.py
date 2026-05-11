import os
import random
import ursa_bbs_signatures as bbs
import bbs_iss.interfaces.requests_api as api
import bbs_iss.utils.utils as utils
from bbs_iss.entities.entity import Entity
from bbs_iss.exceptions.exceptions import IssuerNotAvailable, FreshnessValueError, ProofValidityError, IssuerStateError, BitstringExhaustedError
from bbs_iss.interfaces.credential import VerifiableCredential
from datetime import datetime, timedelta, timezone

MOCK_ISSUER_PARAMETERS = {
    "issuer": "Mock-Issuer"
}

class BitstringManager:
    def __init__(self, default_num_bytes: int = 128):
        self.length = default_num_bytes * 8
        self.revocation_bits = bytearray(default_num_bytes)
        self.control_bits = bytearray(default_num_bytes)
        # Initialize with -1 (never assigned)
        self.expiry_epochs = [-1] * self.length

    def get_revocation_bitstring_hex(self) -> str:
        return self.revocation_bits.hex()

    def extend_bitstring(self, amount_bytes: int):
        amount_bits = amount_bytes * 8
        self.length += amount_bits
        self.revocation_bits.extend(bytearray(amount_bytes))
        self.control_bits.extend(bytearray(amount_bytes))
        self.expiry_epochs.extend([-1] * amount_bits)

    def generate_revocation_index(self, current_epoch: int, expiry_epoch: int) -> int:
        start_index = random.randint(0, self.length - 1)
        
        found_index = -1
        for i in range(self.length):
            idx = (start_index - i) % self.length
            
            byte_idx = idx // 8
            bit_offset = idx % 8
            is_assigned = (self.control_bits[byte_idx] >> (7 - bit_offset)) & 1
            
            # Available if never assigned OR its validity has been surpassed
            if not is_assigned or self.expiry_epochs[idx] <= current_epoch:
                found_index = idx
                break
        
        if found_index == -1:
            raise BitstringExhaustedError()

        byte_idx = found_index // 8
        bit_offset = found_index % 8
        
        # Mark as assigned and NOT revoked
        self.control_bits[byte_idx] |= (1 << (7 - bit_offset))
        self.revocation_bits[byte_idx] &= ~(1 << (7 - bit_offset))
        self.expiry_epochs[found_index] = expiry_epoch
        
        return found_index

    def get_status_string(self, current_epoch: int, next_epoch_date: str = "N/A") -> str:
        total = self.length
        assigned_count = 0
        available_count = 0
        revoked_count = 0
        to_be_released = 0
        
        for i in range(self.length):
            byte_idx = i // 8
            bit_offset = i % 8
            
            is_assigned = (self.control_bits[byte_idx] >> (7 - bit_offset)) & 1
            is_revoked = (self.revocation_bits[byte_idx] >> (7 - bit_offset)) & 1
            
            if is_revoked:
                revoked_count += 1
            
            if not is_assigned or self.expiry_epochs[i] <= current_epoch:
                available_count += 1
            else:
                assigned_count += 1
                if self.expiry_epochs[i] == current_epoch + 1:
                    to_be_released += 1
                    
        lines = ["\n" + "-"*50]
        lines.append(f"{'BITSTRING STATUS':^50}")
        lines.append("-" * 50)
        lines.append(f"Total Indices:      {total}")
        lines.append(f"Available Indices:  {available_count}")
        lines.append(f"Assigned Indices:   {assigned_count}")
        lines.append(f"Revoked Indices:    {revoked_count}")
        lines.append(f"Releasing Next:     {to_be_released} (Epoch {current_epoch + 1})")
        lines.append(f"Next Epoch Date:    {next_epoch_date}")
        lines.append("-" * 50 + "\n")
        
        return "\n".join(lines)

    def revoke_index(self, index: int):
        if index < 0 or index >= self.length:
            raise ValueError(f"Index {index} out of bounds")
        
        byte_idx = index // 8
        bit_offset = index % 8
        self.revocation_bits[byte_idx] |= (1 << (7 - bit_offset))

class IssuerInstance(Entity):
    DEFAULT_EPOCH_SIZE_DAYS = 49
    DEFAULT_RE_ISSUANCE_WINDOW_DAYS = 7
    DEFAULT_BASELINE_DATE_STR = "2026-01-01T00:00:00Z"
    
    class State:
        def __init__(self):
            self.available = True
            self.freshness = None
            self.type = None
            self.pending_data = None

        def start_interaction(self, type: api.RequestType, nonce, pending_data=None):
            self.freshness = nonce
            self.available = False
            self.type = type
            self.pending_data = pending_data

        def end_interaction(self):
            self.freshness = None
            self.available = True
            self.type = None
            self.pending_data = None
            
        @property
        def re_issuance_ready(self) -> bool:
            return (not self.available and self.type == api.RequestType.RE_ISSUANCE and self.freshness is not None)

        @property
        def registry_interaction_ready(self) -> bool:
            return (not self.available and self.type in [api.RequestType.REGISTER_ISSUER_DETAILS, api.RequestType.UPDATE_ISSUER_DETAILS])
    
    def __init__(self, _private_key_pair: bbs.BlsKeyPair = None):
        self.state = self.State()
        if _private_key_pair is None:
            self._private_key_pair = self.key_gen()
            self.public_key = api.PublicKeyBLS(self._private_key_pair.public_key)
        else:
            self._private_key_pair = _private_key_pair
            self.public_key = api.PublicKeyBLS(self._private_key_pair.public_key) 
        self.epoch_size_days = None
        self.re_issuance_window_days = None
        self.issuer_parameters = None
        self.baseline_date = None
        self.bitstring_manager = BitstringManager()
        
    @property
    def available(self) -> bool:
        """Returns True if the Issuer is not currently in an active interaction."""
        return self.state.available

    def reset(self):
        """Manually resets the Issuer state, cancelling any active interaction."""
        self.state.end_interaction()

    def _get_epoch_params(self):
        days = self.epoch_size_days if self.epoch_size_days is not None else self.DEFAULT_EPOCH_SIZE_DAYS
        epoch_delta = timedelta(days=days)
        
        current_baseline = self.baseline_date if self.baseline_date else self.DEFAULT_BASELINE_DATE_STR
        baseline = datetime.fromisoformat(current_baseline.replace('Z', '+00:00'))
        
        now = datetime.now(timezone.utc)
        return baseline, epoch_delta, now

    def get_current_epoch(self) -> int:
        baseline, epoch_delta, now = self._get_epoch_params()
        distance = now - baseline
        return int(distance.total_seconds() // epoch_delta.total_seconds())

    def set_epoch_size_days(self, days: int):
        self.epoch_size_days = days
        
    def set_re_issuance_window_days(self, days: int):
        self.re_issuance_window_days = days
        
    def set_issuer_parameters(self, params: dict):
        self.issuer_parameters = params
        
    def set_baseline_date(self, date_str: str):
        self.baseline_date = date_str

    def get_configuration(self) -> str:
        current_params = self.issuer_parameters if self.issuer_parameters else MOCK_ISSUER_PARAMETERS
        current_epoch_size = self.epoch_size_days if self.epoch_size_days is not None else self.DEFAULT_EPOCH_SIZE_DAYS
        current_window = self.re_issuance_window_days if self.re_issuance_window_days is not None else self.DEFAULT_RE_ISSUANCE_WINDOW_DAYS
        current_baseline = self.baseline_date if self.baseline_date else self.DEFAULT_BASELINE_DATE_STR
        
        baseline, epoch_delta, now = self._get_epoch_params()
        num_epochs = self.get_current_epoch()
        current_active_boundary = baseline + epoch_delta * (num_epochs + 1)
            
        current_epoch_starts = (current_active_boundary - epoch_delta).isoformat(timespec='seconds').replace('+00:00', 'Z')
        current_epoch_ends = current_active_boundary.isoformat(timespec='seconds').replace('+00:00', 'Z')

        pk_hex = self.public_key.key.hex()
        pk_short = f"{pk_hex[:10]}...{pk_hex[-10:]}"
        
        lines = ["\n" + "="*50]
        lines.append(f"{'ISSUER CONFIGURATION':^50}")
        lines.append("="*50)
        lines.append(f"Issuer Name:    {current_params.get('issuer', 'Unknown')}")
        lines.append(f"Public Key:     {pk_short}")
        lines.append(f"Baseline Date:  {current_baseline}")
        lines.append(f"Epoch Size:     {current_epoch_size} days")
        lines.append(f"Window Size:    {current_window} days")
        lines.append(f"Current Epoch:  {current_epoch_starts}")
        lines.append(f"                to {current_epoch_ends}")
        
        if current_window > current_epoch_size:
            lines.append("-" * 50)
            lines.append("WARNING: Re-issuance window > epoch size!")
            
        lines.append(self.get_bitstring_status())
        lines.append(f"{'END OF CONFIGURATION':^50}")
        lines.append("="*50 + "\n")
        
        return "\n".join(lines)


    def get_bitstring_status(self) -> str:
        baseline, epoch_delta, now = self._get_epoch_params()
        curr = self.get_current_epoch()
        next_epoch_date = (baseline + epoch_delta * (curr + 1)).isoformat(timespec='seconds').replace('+00:00', 'Z')
        return self.bitstring_manager.get_status_string(curr, next_epoch_date)

    def process_request(self, request: api.Request):
        try:
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
                    raise IssuerStateError("Invalid state for blind sign", state=self.state)
                return self.issue_vc_blind(request)
            elif request.request_type == api.RequestType.FORWARD_VP_AND_CMT:
                if not self.state.re_issuance_ready:
                    raise IssuerStateError("Invalid state for re-issuance", state=self.state)
                return self.re_issue_vc(request)
            elif request.request_type == api.RequestType.ISSUER_DETAILS_RESPONSE:
                if not self.state.registry_interaction_ready:
                    self.state.end_interaction()
                    raise IssuerStateError("Invalid state for receiving issuer details response", state=self.state)
                    
                success = request.issuer_data == self.state.pending_data
                self.state.end_interaction()
                return success
            else:
                raise ValueError(f"Invalid request type: {request.request_type}")
        except IssuerNotAvailable as e:
            return api.ErrorResponse(request.request_type, api.ErrorType.ISSUER_UNAVAILABLE, message=str(e))
        except ProofValidityError as e:
            self.state.end_interaction()
            return api.ErrorResponse(request.request_type, api.ErrorType.VERIFICATION_FAILED, message=str(e))
        except BitstringExhaustedError as e:
            self.state.end_interaction()
            return api.ErrorResponse(request.request_type, api.ErrorType.BITSTRING_EXHAUSTED, message=str(e))
        except IssuerStateError as e:
            self.state.end_interaction()
            return api.ErrorResponse(request.request_type, api.ErrorType.INVALID_STATE, message=str(e))
        except Exception as e:
            self.state.end_interaction()
            return api.ErrorResponse(request.request_type, api.ErrorType.INVALID_REQUEST, message=str(e))

    def blind_sign(self, request: api.BlindSignRequest):
        try:
            ver_commitment_req = bbs.VerifyBlindedCommitmentRequest(
                public_key=api.SigningPublicKey.derive_signing_public_key(self.public_key, request.total_messages).key,
                proof = request.proof,
                blinded_indices=request.messages_with_blinded_indices,
                nonce = self.state.freshness
            )
            if bbs.verify_blinded_commitment(ver_commitment_req) != bbs.SignatureProofStatus.success:
                raise ProofValidityError("Invalid proof of commitment to hidden attributes")
        except Exception as e:
            if isinstance(e, ProofValidityError):
                raise e
            self.state.end_interaction()
            raise ProofValidityError(str(e))

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
        try:
            verification_request = request.vp.prepare_verification_request(
                pub_key=self.public_key,
                nonce=self.state.freshness,
                commitment=request.commitment
            )
            if not bbs.verify_proof(verification_request):
                raise ProofValidityError("Invalid VP proof")
        except Exception as e:
            if isinstance(e, ProofValidityError):
                raise e
            self.state.end_interaction()
            raise ProofValidityError(str(e))

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
        try:
            ver_commitment_req = bbs.VerifyBlindedCommitmentRequest(
                public_key=api.SigningPublicKey.derive_signing_public_key(self.public_key, request.total_messages).key,
                proof=request.proof,
                blinded_indices=request.messages_with_blinded_indices,
                nonce=self.state.freshness
            )
            if bbs.verify_blinded_commitment(ver_commitment_req) != bbs.SignatureProofStatus.success:
                raise ProofValidityError("Invalid proof of commitment to hidden attributes")
        except Exception as e:
            if isinstance(e, ProofValidityError):
                raise e
            self.state.end_interaction()
            raise ProofValidityError(str(e))

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
        
        valid_until = self.generate_valid_until()
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

    def generate_valid_until(self, return_epoch: bool = False) -> str | int:
        baseline, epoch_delta, now = self._get_epoch_params()
        curr_epoch = self.get_current_epoch()
        
        target_epoch = max(1, curr_epoch + 1)
        expiry = baseline + epoch_delta * target_epoch
            
        window = self.re_issuance_window_days if self.re_issuance_window_days is not None else self.DEFAULT_RE_ISSUANCE_WINDOW_DAYS
        if (expiry - now) <= timedelta(days=window):
            target_epoch += 1
            expiry = baseline + epoch_delta * target_epoch
                
        if return_epoch:
            return target_epoch
        return expiry.isoformat(timespec='seconds').replace('+00:00', 'Z')

    def generate_revocation_index(self) -> str:
        curr = self.get_current_epoch()
        expiry_epoch_num = self.generate_valid_until(return_epoch=True)
        idx = self.bitstring_manager.generate_revocation_index(curr, expiry_epoch_num)
        return f"{idx:x}"

    def revoke_index(self, index: str):
        self.bitstring_manager.revoke_index(int(index, 16))

    def extend_bitstring(self, amount_bytes: int):
        self.bitstring_manager.extend_bitstring(amount_bytes)

    def freshness_response(self, request_type: api.RequestType):
        nonce = utils.gen_nonce()
        self.state.start_interaction(request_type, nonce)
        return api.FreshnessUpdateResponse(nonce)

    def register_issuer(self) -> api.RegisterIssuerDetailsRequest:
        issuer_name = self.issuer_parameters["issuer"] if self.issuer_parameters and "issuer" in self.issuer_parameters else MOCK_ISSUER_PARAMETERS["issuer"]
        epoch_size = self.epoch_size_days if self.epoch_size_days is not None else self.DEFAULT_EPOCH_SIZE_DAYS
        window_days = self.re_issuance_window_days if self.re_issuance_window_days is not None else self.DEFAULT_RE_ISSUANCE_WINDOW_DAYS
        
        issuer_data = api.IssuerPublicData(
            issuer_name=issuer_name,
            public_key=self.public_key,
            revocation_bitstring=self.bitstring_manager.get_revocation_bitstring_hex(),
            valid_until_weeks=epoch_size // 7,
            validity_window_days=window_days
        )
        
        self.state.start_interaction(api.RequestType.REGISTER_ISSUER_DETAILS, None, pending_data=issuer_data)
        
        return api.RegisterIssuerDetailsRequest(issuer_name, issuer_data)

    def update_issuer_details(self) -> api.UpdateIssuerDetailsRequest:
        issuer_name = self.issuer_parameters["issuer"] if self.issuer_parameters and "issuer" in self.issuer_parameters else MOCK_ISSUER_PARAMETERS["issuer"]
        epoch_size = self.epoch_size_days if self.epoch_size_days is not None else self.DEFAULT_EPOCH_SIZE_DAYS
        window_days = self.re_issuance_window_days if self.re_issuance_window_days is not None else self.DEFAULT_RE_ISSUANCE_WINDOW_DAYS
        
        issuer_data = api.IssuerPublicData(
            issuer_name=issuer_name,
            public_key=self.public_key,
            revocation_bitstring=self.bitstring_manager.get_revocation_bitstring_hex(),
            valid_until_weeks=epoch_size // 7,
            validity_window_days=window_days
        )
        
        self.state.start_interaction(api.RequestType.UPDATE_ISSUER_DETAILS, None, pending_data=issuer_data)
        
        return api.UpdateIssuerDetailsRequest(issuer_name, issuer_data)