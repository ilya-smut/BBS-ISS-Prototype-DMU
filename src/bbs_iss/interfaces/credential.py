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
        "https://www.w3.org/ns/credentials/v2",
        "https://example.org/contexts/student-card-v1"
    ]
    DEFAULT_TYPE = ["VerifiableCredential"]
    META_HASH_KEY = "metaHash"
    META_HASH_PLACEHOLDER = "PLACE-HOLDER-METAHASH"
    VALID_UNTIL_KEY = "validUntil"
    VALID_UNTIL_PLACEHOLDER = "PLACE-HOLDER-VALIDUNTIL"
    REVOCATION_MATERIAL_KEY = "revocationMaterial"
    REVOCATION_MATERIAL_PLACEHOLDER = "PLACE-HOLDER-REVOCATION"

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
    
    @staticmethod
    def prep_body_for_vp(credential, revealed_keys: List[str]) -> Dict[str, Any]:
        """
        Prepares the JSON body for a Verifiable Presentation by stripping 
        non-disclosed fields from the credentialSubject.
        """
        body = credential.to_dict()
        body["proof"] = None # Placeholder for the ZKP
        
        # Filter credentialSubject to only include revealed keys
        # We use a dictionary comprehension to avoid mutation-during-iteration errors
        body["credentialSubject"] = {
            k: v for k, v in credential.credential_subject.items() if k in revealed_keys
        }
        
        return body

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
        

class VerifiablePresentation:
    """
    A mock W3C Verifiable Presentation class for credentials with BBS+ signatures.
    NOTE: Verifiable presentations SHOULD be extremely short-lived and bound to a challenge provided by a verifier. Details for accomplishing this depend on the securing mechanism, the transport protocol, and verifier policies.
    """

    DEFAULT_CONTEXT = [
        "https://www.w3.org/ns/credentials/v2",
        "https://example.org/contexts/student-card-v1"
    ]
    DEFAULT_TYPE = ["VerifiablePresentation"]

    def __init__(self,
        type: Optional[List[str]] = None,
        context: Optional[List[str]] = None,
        verifiableCredential: Optional[Dict[str, Any]] = None):
        self.type = type or self.DEFAULT_TYPE
        self.context = context or self.DEFAULT_CONTEXT
        self.verifiableCredential = verifiableCredential
    
    def from_verifiable_credential(self, credential: VerifiableCredential, revealed_attributes: list[str]):
        verifiableCredential = VerifiableCredential.prep_body_for_vp(credential, revealed_attributes)
        self.type = self.DEFAULT_TYPE
        self.context = self.DEFAULT_CONTEXT
        self.verifiableCredential = verifiableCredential

    def add_proof(self, proof: bytes):
        """Sets the ZKP proof on the embedded verifiable credential."""
        self.verifiableCredential["proof"] = proof

    # ── Serialisation ────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "@context": self.context,
            "type": self.type,
            "verifiableCredential": self._serialise_vc_field()
        }
        return data

    def _serialise_vc_field(self) -> Optional[Dict[str, Any]]:
        """Returns a JSON-safe copy of verifiableCredential, converting any
        bytes proof to hex."""
        if self.verifiableCredential is None:
            return None
        vc_copy = dict(self.verifiableCredential)
        proof = vc_copy.get("proof")
        if isinstance(proof, (bytes, bytearray)):
            vc_copy["proof"] = proof.hex()
        return vc_copy

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VerifiablePresentation:
        vc_data = data.get("verifiableCredential")
        if vc_data is not None:
            vc_data = dict(vc_data)
            proof_hex = vc_data.get("proof")
            if isinstance(proof_hex, str):
                vc_data["proof"] = bytes.fromhex(proof_hex)

        return cls(
            type=data.get("type"),
            context=data.get("@context"),
            verifiableCredential=vc_data
        )

    def to_json(self, indent: int = 4) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> VerifiablePresentation:
        data = json.loads(json_str)
        return cls.from_dict(data)

    # ── Meta-field normalisation & nonce binding ────────────────────

    def normalize_meta_fields(self) -> str:
        """
        Incrementally hashes the VP envelope and the embedded credential
        envelope via blake2b, producing a deterministic hex digest.

        Hashed components (in order):
            1. VP  @context  — each context string
            2. VP  type      — each type string
            3. VC  @context  — each context string from the embedded credential
            4. VC  type      — each type string  from the embedded credential
            5. VC  issuer
            6. VC  credentialSubject — *keys only* (revealed), in dict order
            7. VC  proof     — marker only (the value is variable, not hashed)

        Returns
        -------
        str
            Hex-encoded blake2b digest (32 bytes / 64 hex chars).
        """
        h = hashlib.blake2b(digest_size=32)
        vc = self.verifiableCredential

        # The byte-string tags (e.g. b'@context', b'vc.@context') are
        # schema-level domain separation constants. They prevent cross-field
        # and cross-level hash collisions. The exact tag values are arbitrary
        # but must be identical on both Holder and Verifier sides.

        # ── VP envelope ──
        h.update(b'@context')
        for ctx in self.context:
            h.update(ctx.encode())

        h.update(b'type')
        for t in self.type:
            h.update(t.encode())

        # ── Embedded credential envelope ──
        h.update(b'vc.@context')
        for ctx in vc.get("@context", []):
            h.update(ctx.encode())

        h.update(b'vc.type')
        for t in vc.get("type", []):
            h.update(t.encode())

        h.update(b'vc.issuer')
        h.update(vc.get("issuer", "").encode())

        # Only the *keys* of the revealed credentialSubject are hashed;
        # the values are already protected by the BBS+ proof.
        h.update(b'vc.credentialSubject')
        for key in vc.get("credentialSubject", {}).keys():
            h.update(key.encode())

        h.update(b'vc.proof')

        return h.hexdigest()

    def build_bound_nonce(self, nonce: bytes) -> bytes:
        """
        Produces an *effective nonce* that binds the VP's metadata to the
        verifier's challenge nonce.

        ``effective_nonce = blake2b(nonce || meta_hash_bytes)``

        Both the Holder (at proof-creation time) and the Verifier (at
        proof-verification time) must call this method with the same
        original nonce to obtain the same effective nonce.

        Parameters
        ----------
        nonce : bytes
            The original nonce supplied by the verifier.

        Returns
        -------
        bytes
            The bound nonce (32-byte blake2b digest).
        """
        meta_hash_bytes = bytes.fromhex(self.normalize_meta_fields())
        h = hashlib.blake2b(digest_size=32)
        h.update(nonce)
        h.update(meta_hash_bytes)
        return h.digest()

    # ── Verification ─────────────────────────────────────────────────

    def prepare_verification_request(
        self,
        pub_key: PublicKeyBLS,
        nonce: bytes,
    ):
        """
        Constructs a ``bbs.VerifyProofRequest`` for this presentation.

        The total number of original messages (revealed + hidden) is derived
        directly from the proof bytes via ``bbs.get_total_message_count``,
        so the verifier does not need to know the credential schema size
        in advance.

        Parameters
        ----------
        pub_key : PublicKeyBLS
            The issuer's BLS12-381 G2 public key.
        nonce : bytes
            The *original* nonce supplied by the verifier (before binding).
            This method applies ``build_bound_nonce`` internally.

        Returns
        -------
        bbs.VerifyProofRequest
        """
        # The proof stored in the VP is the ZKP (not the original BBS signature)
        proof = self.verifiableCredential["proof"]

        # Total message count is encoded in the proof itself
        total_messages = bbs.get_total_message_count(proof)

        # Derive the BBS signing public key for the original message count
        bls_key_pair = bbs.BlsKeyPair(public_key=pub_key.key)
        bbs_public_key = bls_key_pair.get_bbs_key(total_messages)

        # Extract revealed messages from the credential subject values
        revealed_messages = list(
            self.verifiableCredential["credentialSubject"].values()
        )

        # Bind VP metadata to the verifier's nonce
        bound_nonce = self.build_bound_nonce(nonce)

        request = bbs.VerifyProofRequest(
            public_key=bbs_public_key,
            proof=proof,
            messages=revealed_messages,
            nonce=bound_nonce
        )
        return request