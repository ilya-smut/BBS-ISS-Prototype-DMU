import pytest
from bbs_iss.entities.issuer import BitstringManager
from bbs_iss.exceptions.exceptions import BitstringExhaustedError

def test_bitstring_manager_init():
    manager = BitstringManager(default_num_bytes=2)
    assert manager.length == 16
    assert len(manager.revocation_bits) == 2
    assert len(manager.control_bits) == 2
    assert len(manager.expiry_epochs) == 16
    assert all(e == -1 for e in manager.expiry_epochs)
    assert manager.get_revocation_bitstring_hex() == "0000"

def test_bitstring_manager_allocation():
    manager = BitstringManager(default_num_bytes=1)
    
    # Allocate all bits
    indices = []
    for _ in range(8):
        idx = manager.generate_revocation_index(current_epoch=10, expiry_epoch=20)
        assert idx not in indices
        indices.append(idx)
        
    assert len(indices) == 8
    assert all(0 <= i < 8 for i in indices)
    
    # Try to allocate 9th bit -> should fail
    with pytest.raises(BitstringExhaustedError):
        manager.generate_revocation_index(current_epoch=10, expiry_epoch=20)

def test_bitstring_manager_reuse():
    manager = BitstringManager(default_num_bytes=1)
    
    # Fill up
    for i in range(8):
        manager.generate_revocation_index(current_epoch=0, expiry_epoch=10)
        
    # All bits expire at 10.
    # At epoch 9, still full
    with pytest.raises(BitstringExhaustedError):
        manager.generate_revocation_index(current_epoch=9, expiry_epoch=20)
        
    # At epoch 10, should be reusable
    idx = manager.generate_revocation_index(current_epoch=10, expiry_epoch=20)
    assert 0 <= idx < 8
    assert manager.expiry_epochs[idx] == 20

def test_bitstring_manager_extension():
    manager = BitstringManager(default_num_bytes=1)
    manager.extend_bitstring(1)
    
    assert manager.length == 16
    assert len(manager.revocation_bits) == 2
    assert len(manager.control_bits) == 2
    assert len(manager.expiry_epochs) == 16
    
    # Verify we can allocate up to 16 now
    for _ in range(16):
        manager.generate_revocation_index(current_epoch=0, expiry_epoch=10)
        
    with pytest.raises(BitstringExhaustedError):
        manager.generate_revocation_index(current_epoch=0, expiry_epoch=10)

def test_bitstring_manager_revocation():
    manager = BitstringManager(default_num_bytes=1)
    idx = manager.generate_revocation_index(current_epoch=0, expiry_epoch=10)
    
    assert manager.revocation_bits[0] == 0
    manager.revoke_index(idx)
    
    byte_idx = idx // 8
    bit_offset = idx % 8
    assert (manager.revocation_bits[byte_idx] >> (7 - bit_offset)) & 1 == 1

def test_bitstring_manager_reset_on_reassign():
    manager = BitstringManager(default_num_bytes=1) # 8 bits
    
    # 1. Fill up all 8 bits so any further allocation MUST be a reassignment
    indices = []
    for _ in range(8):
        indices.append(manager.generate_revocation_index(current_epoch=0, expiry_epoch=1))
    
    # 2. Revoke one of the assigned bits
    target_idx = indices[4]
    manager.revoke_index(target_idx)
    
    # Verify it is actually revoked
    assert (manager.revocation_bits[target_idx // 8] >> (7 - (target_idx % 8))) & 1 == 1
    
    # 3. Reassign bits at epoch 1 (when they all expire)
    # We'll reassign all 8 bits to be sure we hit the one we revoked
    for _ in range(8):
        new_idx = manager.generate_revocation_index(current_epoch=1, expiry_epoch=2)
        
        # 4. Verify that the bit is RESET to 0 (valid) upon reassignment
        byte_idx = new_idx // 8
        bit_offset = new_idx % 8
        assert (manager.revocation_bits[byte_idx] >> (7 - bit_offset)) & 1 == 0
