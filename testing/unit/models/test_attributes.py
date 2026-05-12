import pytest
from bbs_iss.interfaces.requests_api import IssuanceAttributes, AttributeType, PublicKeyBLS
from bbs_iss.exceptions.exceptions import NoBlindedAttributes

def test_commitment_requires_hidden_attributes():
    """Assert NoBlindedAttributes is raised when generating a commitment without hidden metadata."""
    attrs = IssuanceAttributes()
    attrs.append("name", "Alice", AttributeType.REVEALED)
    attrs.append("age", "30", AttributeType.REVEALED)
    
    # A fake 96-byte BLS public key for testing
    fake_pub_key = PublicKeyBLS(public_key=b"\x00" * 96)
    
    with pytest.raises(NoBlindedAttributes):
        attrs.build_commitment_append_meta(b"nonce", fake_pub_key)

def test_attribute_sequencing_and_indexing():
    """Assert index values are assigned such that all revealed attributes precede hidden attributes."""
    attrs = IssuanceAttributes()
    attrs.append("first", "1", AttributeType.REVEALED)
    attrs.append("second", "2", AttributeType.HIDDEN)
    attrs.append("third", "3", AttributeType.REVEALED)
    attrs.append("fourth", "4", AttributeType.HIDDEN)
    
    # Need to call build_commitment_append_meta to trigger index assignment
    import ursa_bbs_signatures as bbs
    fake_key_pair = bbs.BlsKeyPair.generate_g2(seed=b"\x00"*32)
    fake_pub_key = PublicKeyBLS(public_key=fake_key_pair.public_key)
    attrs.build_commitment_append_meta(b"nonce", fake_pub_key)
    
    revealed = attrs.attributes
    assert len(revealed) == 5 # 2 original + 3 meta attributes
    assert revealed[0].index == 0
    assert revealed[1].index == 1
    assert revealed[2].index == 2
    assert revealed[3].index == 3
    assert revealed[4].index == 4
    
    hidden = attrs.blinded_attributes
    assert len(hidden) == 2
    assert hidden[0].index == 5
    assert hidden[1].index == 6
    
    # Assert attributes_to_list correctly interpolates them
    full_list = attrs.attributes_to_list()
    assert len(full_list) == 7
    assert full_list[0] == "1"
    assert full_list[1] == "3"
    assert full_list[2] == "PLACE-HOLDER-VALIDUNTIL"
    assert full_list[3] == "PLACE-HOLDER-REVOCATION"
    assert full_list[4] == "PLACE-HOLDER-METAHASH"
    assert full_list[5] == "2"
    assert full_list[6] == "4"
