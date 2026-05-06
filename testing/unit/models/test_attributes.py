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
    """Assert index values are assigned sequentially regardless of their logical type (REVEALED vs HIDDEN)."""
    attrs = IssuanceAttributes()
    attrs.append("first", "1", AttributeType.REVEALED)
    attrs.append("second", "2", AttributeType.HIDDEN)
    attrs.append("third", "3", AttributeType.REVEALED)
    attrs.append("fourth", "4", AttributeType.HIDDEN)
    
    assert attrs.size == 4
    
    revealed = attrs.attributes
    assert len(revealed) == 2
    assert revealed[0].index == 0
    assert revealed[1].index == 2
    
    hidden = attrs.blinded_attributes
    assert len(hidden) == 2
    assert hidden[0].index == 1
    assert hidden[1].index == 3
    
    # Assert attributes_to_list correctly interpolates them
    full_list = attrs.attributes_to_list()
    assert len(full_list) == 4
    assert full_list[0] == "1"
    assert full_list[1] == "2"
    assert full_list[2] == "3"
    assert full_list[3] == "4"
