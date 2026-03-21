import pytest
import copy
from bbs_iss.interfaces.credential import VerifiableCredential
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
import bbs_iss.interfaces.requests_api as api

def test_order_preserving_hashing():
    """Verify identical attributes inserted in a different order produce a different metaHash."""
    vc1 = VerifiableCredential(issuer="did:example:123", credential_subject={})
    vc1.credential_subject["attr1"] = "value1"
    vc1.credential_subject["attr2"] = "value2"

    vc2 = VerifiableCredential(issuer="did:example:123", credential_subject={})
    vc2.credential_subject["attr2"] = "value2"
    vc2.credential_subject["attr1"] = "value1"

    assert vc1.normalize_meta_fields() != vc2.normalize_meta_fields()

def test_hash_changes_on_modification():
    """Verify modifying any value in @context, type, issuer, or credentialSubject changes the metaHash."""
    vc = VerifiableCredential(issuer="did:example:123", credential_subject={})
    vc.credential_subject["attr1"] = "value1"
    base_hash = vc.normalize_meta_fields()

    # Modify context
    vc_ctx = copy.deepcopy(vc)
    vc_ctx.context.append("https://example.com/custom")
    assert vc_ctx.normalize_meta_fields() != base_hash

    # Modify type
    vc_type = copy.deepcopy(vc)
    vc_type.type.append("CustomCredential")
    assert vc_type.normalize_meta_fields() != base_hash

    # Modify issuer
    vc_iss = copy.deepcopy(vc)
    vc_iss.issuer = "did:example:456"
    assert vc_iss.normalize_meta_fields() != base_hash

    # Modify subject key rather than value, since normalize_meta_fields only hashes keys
    vc_sub = copy.deepcopy(vc)
    del vc_sub.credential_subject["attr1"]
    vc_sub.credential_subject["attr2"] = "value1"
    assert vc_sub.normalize_meta_fields() != base_hash

def test_serialization_roundtrip():
    """Validate to_dict, from_dict, to_json, and from_json cleanly roundtrip the credential without data loss or reordering."""
    vc = VerifiableCredential(issuer="did:example:123", credential_subject={})
    vc.credential_subject["attr1"] = "value1"
    vc.credential_subject["attr2"] = "value2"
    vc.proof = b"some-proof"

    vc_dict = vc.to_dict()
    vc_from_dict = VerifiableCredential.from_dict(vc_dict)
    assert vc_from_dict.context == vc.context
    assert vc_from_dict.type == vc.type
    assert vc_from_dict.issuer == vc.issuer
    assert list(vc_from_dict.credential_subject.keys()) == list(vc.credential_subject.keys())
    assert vc_from_dict.credential_subject == vc.credential_subject
    assert vc_from_dict.proof == vc.proof

    vc_json = vc.to_json()
    vc_from_json = VerifiableCredential.from_json(vc_json)
    assert vc_from_json.context == vc.context
    assert list(vc_from_json.credential_subject.keys()) == list(vc.credential_subject.keys())
    assert vc_from_json.credential_subject == vc.credential_subject


@pytest.fixture
def issuance_setup():
    """Fixture to execute a valid issuance and return the holder, issuer, and the valid credential."""
    issuer = IssuerInstance()
    holder = HolderInstance()

    attributes = api.IssuanceAttributes()
    attributes.append("name", "Alice", api.AttributeType.REVEALED)
    attributes.append("ssn", "123-45", api.AttributeType.HIDDEN)

    init_req = holder.issuance_request(
        issuer_pub_key=issuer.public_key,
        attributes=attributes,
        cred_name="test-cred"
    )
    freshness = issuer.process_request(init_req)
    blind_req = holder.process_request(freshness)
    forward_vc = issuer.process_request(blind_req)
    
    # Store credential in holder and verify
    assert holder.process_request(forward_vc) is True
    vc = holder.credentials["test-cred"]
    return holder, issuer, vc

def test_signature_invalid_on_context_change(issuance_setup):
    holder, issuer, vc = issuance_setup
    vc_mutated = VerifiableCredential.from_dict(vc.to_dict())
    vc_mutated.context.append("https://example.com/fake")
    assert not holder.verify_vc(issuer.public_key, vc=vc_mutated)

def test_signature_invalid_on_type_change(issuance_setup):
    holder, issuer, vc = issuance_setup
    vc_mutated = VerifiableCredential.from_dict(vc.to_dict())
    vc_mutated.type.append("FakeCredential")
    assert not holder.verify_vc(issuer.public_key, vc=vc_mutated)

def test_signature_invalid_on_issuer_change(issuance_setup):
    holder, issuer, vc = issuance_setup
    vc_mutated = VerifiableCredential.from_dict(vc.to_dict())
    vc_mutated.issuer = "did:fake:bad"
    assert not holder.verify_vc(issuer.public_key, vc=vc_mutated)

def test_signature_invalid_on_subject_change(issuance_setup):
    holder, issuer, vc = issuance_setup
    vc_mutated = VerifiableCredential.from_dict(vc.to_dict())
    # Modify a revealed attribute
    vc_mutated.credential_subject["name"] = "Mallory"
    assert not holder.verify_vc(issuer.public_key, vc=vc_mutated)
    
    vc_mutated2 = VerifiableCredential.from_dict(vc.to_dict())
    # Modify a hidden attribute
    vc_mutated2.credential_subject["ssn"] = "999-99"
    assert not holder.verify_vc(issuer.public_key, vc=vc_mutated2)
