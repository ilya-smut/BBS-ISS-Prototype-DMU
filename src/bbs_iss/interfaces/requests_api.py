from __future__ import annotations
import ursa_bbs_signatures as bbs
from enum import Enum
from typing import TYPE_CHECKING
from bbs_iss.exceptions.exceptions import AttributesNotCommitted, NoBlindedAttributes, NoRevealedAttributes
from bbs_iss.interfaces.credential import VerifiableCredential


class PublicKeyBLS:
    def __init__(self, public_key: bytes):
        self.key = public_key


class SigningPublicKey:
    def __init__(self, signing_public_key: bytes):
        self.key = signing_public_key

    @staticmethod
    def derive_signing_public_key(public_key: PublicKeyBLS, total_messages: int):
        _key_pair = bbs.BlsKeyPair(public_key=public_key.key)
        signing_public_key = _key_pair.get_bbs_key(total_messages)
        return SigningPublicKey(signing_public_key)


class AttributeType(Enum):
    REVEALED = 1
    HIDDEN = 2

class KeyedIndexedMessage(bbs.IndexedMessage):
    def __init__(self, index: int, message: str, key: str):
        super().__init__(message=message, index=index)
        self.key = key

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


class Request:
    def __init__(self, request_type: RequestType):
        self.request_type = request_type


class VCIssuanceRequest(Request):
    def __init__(self):
        super().__init__(RequestType.ISSUANCE)


class BlindSignRequest(Request):
    def __init__(self, attributes: IssuanceAttributes):
        super().__init__(RequestType.BLIND_SIGN)
        self.revealed_attributes = attributes.get_revealed_attributes()
        self.commitment = attributes.get_commitment()
        self.total_messages = attributes.size
        self.proof = attributes.get_proof()
        self.messages_with_blinded_indices = attributes.get_messages_with_blinded_indices()


class FreshnessUpdateResponse(Request):
    def __init__(self, nonce: bytes):
        super().__init__(RequestType.FRESHNESS)
        self.nonce = nonce

class ForwardVCResponse(Request):
    def __init__(self, vc: VerifiableCredential):
        super().__init__(RequestType.FORWARD_VC)
        self.vc = vc
