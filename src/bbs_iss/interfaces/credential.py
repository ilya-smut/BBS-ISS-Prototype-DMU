from __future__ import annotations
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from bbs_iss.interfaces.requests_api import KeyedIndexedMessage


class VerifiableCredential:
    """
    A mock W3C Verifiable Credential class for BBS+ signatures.
    """
    DEFAULT_CONTEXT = [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/bbs/v1"
    ]
    DEFAULT_TYPE = ["VerifiableCredential"]

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
    def parse_keyed_indexed_messages(messages: list[KeyedIndexedMessage]) -> Dict[str, str]:
        sorted_messages = sorted(messages, key=lambda x: x.index)
        parsed_messages = {}
        for message in sorted_messages:
            parsed_messages[message.key] = message.message
        return parsed_messages
        