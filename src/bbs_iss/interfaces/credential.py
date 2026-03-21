from __future__ import annotations
import hashlib
import json
from datetime import datetime
import ursa_bbs_signatures as bbs
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from bbs_iss.interfaces.requests_api import KeyedIndexedMessage, PublicKeyBLS


class VerifiableCredential:
    """
    A mock W3C Verifiable Credential class for BBS+ signatures.
    """
    DEFAULT_CONTEXT = [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/bbs/v1"
    ]
    DEFAULT_TYPE = ["VerifiableCredential"]
    META_HASH_KEY = "metaHash"
    META_HASH_PLACEHOLDER = "PLACE-HOLDER-METAHASH"

    def __init__(
        self,
        issuer: str,
        credential_subject: Dict[str, Any],
        type: Optional[List[str]] = None,
        context: Optional[List[str]] = None,
        proof: Optional[bytes] = None
    ):
        self.context = context or self.DEFAULT_CONTEXT
        self.type = type or (self.DEFAULT_TYPE + ["MockCredential"])
        self.issuer = issuer
        self.credential_subject = credential_subject
        self.proof = proof

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "@context": self.context,
            "type": self.type,
            "issuer": self.issuer,
            "credentialSubject": self.credential_subject
        }
        if self.proof:
            data["proof"] = self.proof.hex()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VerifiableCredential:
        proof_hex = data.get("proof")
        proof = bytes.fromhex(proof_hex) if proof_hex else None
        
        return cls(
            issuer=data.get("issuer"),
            credential_subject=data.get("credentialSubject"),
            type=data.get("type"),
            context=data.get("@context"),
            proof=proof
        )

    def to_json(self, indent: int = 4) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> VerifiableCredential:
        data = json.loads(json_str)
        return cls.from_dict(data)

    @staticmethod
    def parse_sorted_keyed_indexed_messages(messages: list[KeyedIndexedMessage]) -> Dict[str, str]:
        sorted_messages = sorted(messages, key=lambda x: x.index)
        parsed_messages = {}
        for message in sorted_messages:
            parsed_messages[message.key] = message.message
        return parsed_messages
    
    def prepare_verification_request(self, pub_key: PublicKeyBLS):
        messages = self.credential_subject.copy() # copying to avoid changing the original credential subject
        messages[self.META_HASH_KEY] = self.normalize_meta_fields() # Calculating new metaHash
        message_list=list(messages.values()) # converting to list of messages
        request = bbs.VerifyRequest(
            key_pair=bbs.BlsKeyPair(public_key=pub_key.key),
            signature=self.proof,
            messages=message_list
        )
        return request
    
    def normalize_meta_fields(self) -> str:
        """
        {
            '@context': [context_strings],
            'type': [type_strings],
            'issuer': 'Issuer-name',
            'credentialSubject': {
                'key1': 'value1',
                'key2': 'value2'
            },
            'proof': 'ProofBytes'
        } --> incremental hashing of ['@context', [context_strings], 'type', [type_strings], 'issuer', 'Issuer-name', 'credentialSubject', ['key1', 'key2', ...], 'proof'] --> HashValue

        Incrementally hashes each component via blake2b to avoid
        building a large intermediate concatenated string.
        """
        h = hashlib.blake2b(digest_size=32)

        # @context
        h.update(b'@context')
        for ctx in self.context:
            h.update(ctx.encode())

        # type
        h.update(b'type')
        for t in self.type:
            h.update(t.encode())

        # issuer
        h.update(b'issuer')
        h.update(self.issuer.encode())

        # credentialSubject — keys in original order (order-sensitive for BBS message indexing)
        h.update(b'credentialSubject')
        for key in self.credential_subject.keys():
            h.update(key.encode())

        # proof
        h.update(b'proof')

        return h.hexdigest()
        