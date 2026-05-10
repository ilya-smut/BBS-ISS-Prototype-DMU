from __future__ import annotations
import ursa_bbs_signatures as bbs
import json
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, Optional
from dataclasses import dataclass
from bbs_iss.exceptions.exceptions import AttributesNotCommitted, NoBlindedAttributes, NoRevealedAttributes
from bbs_iss.interfaces.credential import VerifiableCredential, VerifiablePresentation


class PublicKeyBLS:
    def __init__(self, public_key: bytes):
        self.key = public_key

    def __eq__(self, other):
        if not isinstance(other, PublicKeyBLS):
            return False
        return self.key == other.key

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key.hex()}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PublicKeyBLS:
        return cls(bytes.fromhex(data["key"]))


class SigningPublicKey:
    def __init__(self, signing_public_key: bytes):
        self.key = signing_public_key

    @staticmethod
    def derive_signing_public_key(public_key: PublicKeyBLS, total_messages: int):
        _key_pair = bbs.BlsKeyPair(public_key=public_key.key)
        signing_public_key = _key_pair.get_bbs_key(total_messages)
        return SigningPublicKey(signing_public_key)


@dataclass
class IssuerPublicData:
    issuer_name: str
    public_key: PublicKeyBLS
    revocation_bitstring: str
    valid_until_weeks: int
    validity_window_days: int

    def check_revocation_status(self, bit_index_hex: str) -> bool:
        """
        Checks if the credential at the given bit_index_hex is revoked.
        The revocation_bitstring is expected to be a hex-encoded bitstring.
        Bit 0 is the MSB of the first byte.
        Returns True if revoked (bit is 1), False if valid (bit is 0).
        If the index is out of bounds, it is considered valid (False).
        """
        try:
            bit_index = int(bit_index_hex, 16)
            bitstring_bytes = bytes.fromhex(self.revocation_bitstring)
        except (ValueError, TypeError):
            return False
            
        byte_index = bit_index // 8
        bit_offset = bit_index % 8
        
        if byte_index < 0 or byte_index >= len(bitstring_bytes):
            return False
            
        # Check if the bit at the specified index is set to 1
        return bool((bitstring_bytes[byte_index] >> (7 - bit_offset)) & 1)

    def get_print_string(self) -> str:
        pk_hex = self.public_key.key.hex()
        pk_short = f"{pk_hex[:10]}...{pk_hex[-10:]}"
        lines = ["\n" + "="*50]
        lines.append(f"{'ISSUER PUBLIC DATA':^50}")
        lines.append("="*50)
        lines.append(f"Issuer Name:    {self.issuer_name}")
        lines.append(f"Public Key:     {pk_short}")
        lines.append(f"Revocation:     {len(self.revocation_bitstring) * 4} bits")
        lines.append(f"Epoch Size:     {self.validity_window_days} days")
        lines.append(f"Valid For:      {self.valid_until_weeks} weeks")
        lines.append("="*50 + "\n")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "issuer_name": self.issuer_name,
            "public_key": self.public_key.to_dict(),
            "revocation_bitstring": self.revocation_bitstring,
            "valid_until_weeks": self.valid_until_weeks,
            "validity_window_days": self.validity_window_days
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> IssuerPublicData:
        return cls(
            issuer_name=data["issuer_name"],
            public_key=PublicKeyBLS.from_dict(data["public_key"]),
            revocation_bitstring=data["revocation_bitstring"],
            valid_until_weeks=data["valid_until_weeks"],
            validity_window_days=data["validity_window_days"]
        )

    def to_json(self, indent: int = 4) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> IssuerPublicData:
        return cls.from_dict(json.loads(json_str))


@dataclass
class CacheEntry:
    issuer_data: IssuerPublicData
    obtained_at: str  # ISO 8601 timestamp (UTC)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "issuer_data": self.issuer_data.to_dict(),
            "obtained_at": self.obtained_at
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CacheEntry:
        return cls(
            issuer_data=IssuerPublicData.from_dict(data["issuer_data"]),
            obtained_at=data["obtained_at"]
        )

    def to_json(self, indent: int = 4) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> CacheEntry:
        return cls.from_dict(json.loads(json_str))


class AttributeType(Enum):
    REVEALED = 1
    HIDDEN = 2

class KeyedIndexedMessage(bbs.IndexedMessage):
    def __init__(self, index: int, message: str, key: str):
        super().__init__(message=message, index=index)
        self.key = key

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "message": self.message,
            "key": self.key
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> KeyedIndexedMessage:
        return cls(index=data["index"], message=data["message"], key=data["key"])

class IssuanceAttributes:
    def __init__(self):
        self.size = 0
        self.attributes: list[KeyedIndexedMessage] = []
        self.blinded_attributes: list[KeyedIndexedMessage] = []
        self.messages_with_blinded_indices: list[KeyedIndexedMessage] = [] # Workaround due to the way the library is implemented
        self._committed = False
        self._commitment = None
        self._blinding_factor = None


    def append(self, key: str, attribute: str, type: AttributeType = AttributeType.REVEALED):
        if type == AttributeType.REVEALED:
            self.attributes.append(KeyedIndexedMessage(index=self.size, message=attribute, key=key))
        elif type == AttributeType.HIDDEN:
            self.blinded_attributes.append(KeyedIndexedMessage(index=self.size, message=attribute, key=key))
            self.messages_with_blinded_indices.append(KeyedIndexedMessage(index=self.size, message="", key=key)) # Workaround due to the way the library is implemented
        self.size += 1


    def build_commitment_append_meta(self, nonce: bytes, public_key: PublicKeyBLS):
        self.append(VerifiableCredential.VALID_UNTIL_KEY, VerifiableCredential.VALID_UNTIL_PLACEHOLDER, AttributeType.REVEALED)
        self.append(VerifiableCredential.REVOCATION_MATERIAL_KEY, VerifiableCredential.REVOCATION_MATERIAL_PLACEHOLDER, AttributeType.REVEALED)
        self.append(VerifiableCredential.META_HASH_KEY, VerifiableCredential.META_HASH_PLACEHOLDER, AttributeType.REVEALED)
        if not self.blinded_attributes:
            raise NoBlindedAttributes()
        commit_req = bbs.CreateBlindedCommitmentRequest(
            public_key=SigningPublicKey.derive_signing_public_key(public_key, self.size).key,
            messages=self.blinded_attributes,
            nonce=nonce
        )
        blinded_commitment = bbs.create_blinded_commitment(commit_req)
        self._commitment: bytes = blinded_commitment.commitment
        self._blinding_factor: bytes = blinded_commitment.blinding_factor
        self._proof: bytes = blinded_commitment.blind_sign_context
        self._committed: bool = True
    

    def get_commitment(self):
        if not self._committed:
            raise AttributesNotCommitted()
        return self._commitment
    

    def get_blinding_factor(self):
        if not self._committed:
            raise AttributesNotCommitted()
        return self._blinding_factor
    

    def get_revealed_attributes(self):
        if not self.attributes:
            raise NoRevealedAttributes()
        return self.attributes


    def get_proof(self):
        if not self._committed:
            raise AttributesNotCommitted()
        return self._proof


    def get_messages_with_blinded_indices(self):
        return self.messages_with_blinded_indices


    def attributes_to_list(self):
        attributes = [None] * self.size
        for attribute in self.attributes:
            attributes[attribute.index] = attribute.message
        for attribute in self.blinded_attributes:
            attributes[attribute.index] = attribute.message
        return attributes


class ErrorType(Enum):
    ISSUER_UNAVAILABLE = 1
    VERIFICATION_FAILED = 2
    BITSTRING_EXHAUSTED = 3
    INVALID_REQUEST = 4
    INVALID_STATE = 5


class RequestType(Enum):
    ISSUANCE = 1
    RE_ISSUANCE = 2
    BLIND_SIGN = 3
    BLIND_RE_SIGN = 4
    FRESHNESS = 5
    VP_REQUEST = 6
    FORWARD_VC = 7
    FORWARD_VP = 8
    VRF_ACKNOWLEDGE = 9
    ERROR = 10
    FORWARD_VP_AND_CMT = 11
    REGISTER_ISSUER_DETAILS = 12
    UPDATE_ISSUER_DETAILS = 13
    GET_ISSUER_DETAILS = 14
    ISSUER_DETAILS_RESPONSE = 15
    BULK_ISSUER_DETAILS_REQUEST = 16
    BULK_ISSUER_DETAILS_RESPONSE = 17


class Request:
    def __init__(self, request_type: RequestType):
        self.request_type = request_type

    def to_dict(self) -> Dict[str, Any]:
        return {"request_type": self.request_type.value}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Request:
        req_type = RequestType(data["request_type"])
        
        # Dispatch table for polymorphic reconstruction
        type_to_class = {
            RequestType.ISSUANCE: VCIssuanceRequest,
            RequestType.BLIND_SIGN: BlindSignRequest,
            RequestType.FRESHNESS: FreshnessUpdateResponse,
            RequestType.FORWARD_VC: ForwardVCResponse,
            RequestType.VP_REQUEST: VPRequest,
            RequestType.FORWARD_VP: ForwardVPResponse,
            RequestType.FORWARD_VP_AND_CMT: ForwardVpAndCmtRequest,
            RequestType.REGISTER_ISSUER_DETAILS: RegisterIssuerDetailsRequest,
            RequestType.UPDATE_ISSUER_DETAILS: UpdateIssuerDetailsRequest,
            RequestType.GET_ISSUER_DETAILS: GetIssuerDetailsRequest,
            RequestType.ISSUER_DETAILS_RESPONSE: IssuerDetailsResponse,
            RequestType.BULK_ISSUER_DETAILS_REQUEST: BulkGetIssuerDetailsRequest,
            RequestType.BULK_ISSUER_DETAILS_RESPONSE: BulkIssuerDetailsResponse,
            RequestType.ERROR: ErrorResponse,
        }
        
        target_class = type_to_class.get(req_type)
        if target_class and cls is Request:
            return target_class.from_dict(data)
        
        # If called on a subclass or no specific class found
        return cls(req_type)

    def to_json(self, indent: int = 4) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> Request:
        return cls.from_dict(json.loads(json_str))

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{self.request_type.name.replace('_', ' '):^50}")
        lines.append("="*50)
        lines.append(f"Type: {self.request_type.name}")
        lines.append("="*50 + "\n")
        return "\n".join(lines)


class ErrorResponse(Request):
    def __init__(self, original_request_type: RequestType, error_type: ErrorType, message: str = ""):
        super().__init__(RequestType.ERROR)
        self.original_request_type = original_request_type
        self.error_type = error_type
        self.message = message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "original_request_type": self.original_request_type.value,
            "error_type": self.error_type.value,
            "message": self.message
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ErrorResponse:
        return cls(
            original_request_type=RequestType(data["original_request_type"]),
            error_type=ErrorType(data["error_type"]),
            message=data.get("message", "")
        )

    def get_print_string(self) -> str:
        lines = ["\n" + "!"*50]
        lines.append(f"{'ERROR RESPONSE':^50}")
        lines.append("!"*50)
        lines.append(f"Original Request: {self.original_request_type.name}")
        lines.append(f"Error Type:       {self.error_type.name}")
        if self.message:
            lines.append(f"Message:          {self.message}")
        lines.append("!"*50 + "\n")
        return "\n".join(lines)


class VCIssuanceRequest(Request):
    def __init__(self):
        super().__init__(RequestType.ISSUANCE)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VCIssuanceRequest:
        return cls()


class BlindSignRequest(Request):
    def __init__(self, attributes: Optional[IssuanceAttributes] = None, **kwargs):
        super().__init__(RequestType.BLIND_SIGN)
        if attributes:
            self.revealed_attributes = attributes.get_revealed_attributes()
            self.commitment = attributes.get_commitment()
            self.total_messages = attributes.size
            self.proof = attributes.get_proof()
            self.messages_with_blinded_indices = attributes.get_messages_with_blinded_indices()
        else:
            self.revealed_attributes = kwargs.get("revealed_attributes")
            self.commitment = kwargs.get("commitment")
            self.total_messages = kwargs.get("total_messages")
            self.proof = kwargs.get("proof")
            self.messages_with_blinded_indices = kwargs.get("messages_with_blinded_indices")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "revealed_attributes": [attr.to_dict() for attr in self.revealed_attributes],
            "commitment": self.commitment.hex(),
            "total_messages": self.total_messages,
            "proof": self.proof.hex(),
            "messages_with_blinded_indices": [attr.to_dict() for attr in self.messages_with_blinded_indices]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BlindSignRequest:
        return cls(
            revealed_attributes=[KeyedIndexedMessage.from_dict(a) for a in data["revealed_attributes"]],
            commitment=bytes.fromhex(data["commitment"]),
            total_messages=data["total_messages"],
            proof=bytes.fromhex(data["proof"]),
            messages_with_blinded_indices=[KeyedIndexedMessage.from_dict(a) for a in data["messages_with_blinded_indices"]]
        )

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{'BLIND SIGN REQUEST':^50}")
        lines.append("="*50)
        lines.append(f"Total Messages:  {self.total_messages}")
        lines.append(f"Commitment & Proof: {self.commitment.hex()[:20]}...")
        lines.append("                    (single value mandated by dependency library)")
        lines.append("\nRevealed Attributes:")
        for attr in self.revealed_attributes:
            lines.append(f"  - {attr.key}: {attr.message}")
        lines.append("\nBlinded Indices:")
        lines.append(f"  {', '.join(str(attr.index) for attr in self.messages_with_blinded_indices)}")
        lines.append("="*50 + "\n")
        return "\n".join(lines)


class FreshnessUpdateResponse(Request):
    def __init__(self, nonce: bytes):
        super().__init__(RequestType.FRESHNESS)
        self.nonce = nonce

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "nonce": self.nonce.hex()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FreshnessUpdateResponse:
        return cls(nonce=bytes.fromhex(data["nonce"]))

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{'FRESHNESS UPDATE':^50}")
        lines.append("="*50)
        lines.append(f"Nonce: {self.nonce.hex()}")
        lines.append("="*50 + "\n")
        return "\n".join(lines)

class ForwardVCResponse(Request):
    def __init__(self, vc: VerifiableCredential):
        super().__init__(RequestType.FORWARD_VC)
        self.vc = vc

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "vc": self.vc.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ForwardVCResponse:
        return cls(vc=VerifiableCredential.from_dict(data["vc"]))

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{'FORWARD VC RESPONSE':^50}")
        lines.append("="*50)
        lines.append("Verifiable Credential:")
        lines.append(self.vc.to_json(indent=4))
        lines.append("="*50 + "\n")
        return "\n".join(lines)

class VPRequest(Request):
    def __init__(self, requested_attributes: list[str], nonce: bytes):
        super().__init__(RequestType.VP_REQUEST)
        self.requested_attributes = requested_attributes
        self.nonce = nonce

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "requested_attributes": self.requested_attributes,
            "nonce": self.nonce.hex()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VPRequest:
        return cls(
            requested_attributes=data["requested_attributes"],
            nonce=bytes.fromhex(data["nonce"])
        )

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{'VP REQUEST':^50}")
        lines.append("="*50)
        lines.append(f"Nonce: {self.nonce.hex()}")
        lines.append("\nRequested Attributes:")
        for attr in self.requested_attributes:
            lines.append(f"  - {attr}")
        lines.append("="*50 + "\n")
        return "\n".join(lines)

class ForwardVPResponse(Request):
    def __init__(self, vp: VerifiablePresentation, pub_key: PublicKeyBLS):
        super().__init__(RequestType.FORWARD_VP)
        self.vp = vp
        self.pub_key = pub_key

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "vp": self.vp.to_dict(),
            "pub_key": self.pub_key.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ForwardVPResponse:
        return cls(
            vp=VerifiablePresentation.from_dict(data["vp"]),
            pub_key=PublicKeyBLS.from_dict(data["pub_key"])
        )

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{'FORWARD VP RESPONSE':^50}")
        lines.append("="*50)
        lines.append(f"Issuer Public Key: {self.pub_key.key.hex()[:20]}...")
        lines.append("\nVerifiable Presentation:")
        lines.append(self.vp.to_json(indent=4))
        lines.append("="*50 + "\n")
        return "\n".join(lines)

class ForwardVpAndCmtRequest(Request):
    def __init__(self, vp: Optional[VerifiablePresentation] = None, attributes: Optional[IssuanceAttributes] = None, **kwargs):
        super().__init__(RequestType.FORWARD_VP_AND_CMT)
        if attributes:
            self.vp = vp
            self.commitment = attributes.get_commitment()
            self.proof = attributes.get_proof()
            self.revealed_attributes = attributes.get_revealed_attributes()
            self.messages_with_blinded_indices = attributes.get_messages_with_blinded_indices()
            self.total_messages = attributes.size
        else:
            self.vp = vp or kwargs.get("vp")
            self.commitment = kwargs.get("commitment")
            self.proof = kwargs.get("proof")
            self.revealed_attributes = kwargs.get("revealed_attributes")
            self.messages_with_blinded_indices = kwargs.get("messages_with_blinded_indices")
            self.total_messages = kwargs.get("total_messages")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "vp": self.vp.to_dict(),
            "commitment": self.commitment.hex(),
            "proof": self.proof.hex(),
            "revealed_attributes": [attr.to_dict() for attr in self.revealed_attributes],
            "messages_with_blinded_indices": [attr.to_dict() for attr in self.messages_with_blinded_indices],
            "total_messages": self.total_messages
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ForwardVpAndCmtRequest:
        return cls(
            vp=VerifiablePresentation.from_dict(data["vp"]),
            commitment=bytes.fromhex(data["commitment"]),
            proof=bytes.fromhex(data["proof"]),
            revealed_attributes=[KeyedIndexedMessage.from_dict(a) for a in data["revealed_attributes"]],
            messages_with_blinded_indices=[KeyedIndexedMessage.from_dict(a) for a in data["messages_with_blinded_indices"]],
            total_messages=data["total_messages"]
        )

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{'FORWARD VP AND COMMITMENT':^50}")
        lines.append("="*50)
        lines.append(f"Total Messages:  {self.total_messages}")
        lines.append(f"Commitment & Proof: {self.commitment.hex()[:20]}...")
        lines.append("                    (single value mandated by dependency library)")
        lines.append("\nVerifiable Presentation:")
        lines.append(self.vp.to_json(indent=4))
        lines.append("\nRevealed Attributes (for re-issuance):")
        for attr in self.revealed_attributes:
            lines.append(f"  - {attr.key}: {attr.message}")
        lines.append("="*50 + "\n")
        return "\n".join(lines)


class RegisterIssuerDetailsRequest(Request):
    def __init__(self, issuer_name: str, issuer_data: IssuerPublicData):
        super().__init__(RequestType.REGISTER_ISSUER_DETAILS)
        self.issuer_name = issuer_name
        self.issuer_data = issuer_data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "issuer_name": self.issuer_name,
            "issuer_data": self.issuer_data.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RegisterIssuerDetailsRequest:
        return cls(
            issuer_name=data["issuer_name"],
            issuer_data=IssuerPublicData.from_dict(data["issuer_data"])
        )

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{'REGISTER ISSUER DETAILS':^50}")
        lines.append("="*50)
        lines.append(f"Issuer Name: {self.issuer_name}")
        lines.append(self.issuer_data.get_print_string())
        lines.append("="*50 + "\n")
        return "\n".join(lines)

class UpdateIssuerDetailsRequest(Request):
    def __init__(self, issuer_name: str, issuer_data: IssuerPublicData):
        super().__init__(RequestType.UPDATE_ISSUER_DETAILS)
        self.issuer_name = issuer_name
        self.issuer_data = issuer_data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "issuer_name": self.issuer_name,
            "issuer_data": self.issuer_data.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> UpdateIssuerDetailsRequest:
        return cls(
            issuer_name=data["issuer_name"],
            issuer_data=IssuerPublicData.from_dict(data["issuer_data"])
        )

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{'UPDATE ISSUER DETAILS':^50}")
        lines.append("="*50)
        lines.append(f"Issuer Name: {self.issuer_name}")
        lines.append(self.issuer_data.get_print_string())
        lines.append("="*50 + "\n")
        return "\n".join(lines)

class GetIssuerDetailsRequest(Request):
    def __init__(self, issuer_name: str):
        super().__init__(RequestType.GET_ISSUER_DETAILS)
        self.issuer_name = issuer_name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "issuer_name": self.issuer_name
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GetIssuerDetailsRequest:
        return cls(issuer_name=data["issuer_name"])

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{'GET ISSUER DETAILS':^50}")
        lines.append("="*50)
        lines.append(f"Issuer Name: {self.issuer_name}")
        lines.append("="*50 + "\n")
        return "\n".join(lines)

class IssuerDetailsResponse(Request):
    def __init__(self, issuer_data: Optional[IssuerPublicData]):
        super().__init__(RequestType.ISSUER_DETAILS_RESPONSE)
        self.issuer_data = issuer_data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "issuer_data": self.issuer_data.to_dict() if self.issuer_data else None
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> IssuerDetailsResponse:
        data_val = data.get("issuer_data")
        return cls(issuer_data=IssuerPublicData.from_dict(data_val) if data_val else None)

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{'ISSUER DETAILS RESPONSE':^50}")
        lines.append("="*50)
        if self.issuer_data:
            lines.append(self.issuer_data.get_print_string())
        else:
            lines.append("Result: NOT FOUND")
        lines.append("="*50 + "\n")
        return "\n".join(lines)


class BulkGetIssuerDetailsRequest(Request):
    def __init__(self):
        super().__init__(RequestType.BULK_ISSUER_DETAILS_REQUEST)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BulkGetIssuerDetailsRequest:
        return cls()


class BulkIssuerDetailsResponse(Request):
    def __init__(self, issuers_data: list[IssuerPublicData]):
        super().__init__(RequestType.BULK_ISSUER_DETAILS_RESPONSE)
        self.issuers_data = issuers_data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_type": self.request_type.value,
            "issuers_data": [data.to_dict() for data in self.issuers_data]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BulkIssuerDetailsResponse:
        return cls(issuers_data=[IssuerPublicData.from_dict(d) for d in data["issuers_data"]])

    def get_print_string(self) -> str:
        lines = ["\n" + "="*50]
        lines.append(f"{'BULK ISSUER DETAILS RESPONSE':^50}")
        lines.append("="*50)
        lines.append(f"Count: {len(self.issuers_data)}")
        for data in self.issuers_data:
            pk_hex = data.public_key.key.hex()
            lines.append(f"  - {data.issuer_name:<20} ({pk_hex[:10]}...)")
        lines.append("="*50 + "\n")
        return "\n".join(lines)

