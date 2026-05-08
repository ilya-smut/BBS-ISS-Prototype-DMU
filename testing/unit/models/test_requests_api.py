import pytest
import json
import bbs_iss.interfaces.requests_api as api

def test_public_key_bls_equality():
    key_bytes = b"test_key_123456789012345678901234"
    pk1 = api.PublicKeyBLS(key_bytes)
    pk2 = api.PublicKeyBLS(key_bytes)
    pk3 = api.PublicKeyBLS(b"other_key_09876543210987654321")
    
    assert pk1 == pk2
    assert pk1 != pk3
    assert pk1 != "not a key"

def test_issuer_public_data_serialization():
    pk = api.PublicKeyBLS(b"some_bls_key_data_32_bytes_long")
    data = api.IssuerPublicData(
        issuer_name="Test-Issuer",
        public_key=pk,
        revocation_bitstring="0011",
        valid_until_weeks=5,
        validity_window_days=10
    )
    
    # Dict serialization
    d = data.to_dict()
    assert d["issuer_name"] == "Test-Issuer"
    assert d["public_key"] == pk.to_dict()
    
    # Dict deserialization
    data2 = api.IssuerPublicData.from_dict(d)
    assert data2 == data # Dataclass equality
    assert data2.public_key == pk
    
    # JSON serialization
    j = data.to_json()
    data3 = api.IssuerPublicData.from_json(j)
    assert data3 == data

def test_cache_entry_serialization():
    pk = api.PublicKeyBLS(b"key")
    issuer_data = api.IssuerPublicData("Iss", pk, "0", 1, 1)
    entry = api.CacheEntry(issuer_data, "2026-05-07T00:00:00Z")
    
    # JSON round-trip
    j = entry.to_json()
    entry2 = api.CacheEntry.from_json(j)
    
    assert entry2.issuer_data.issuer_name == "Iss"
    assert entry2.obtained_at == "2026-05-07T00:00:00Z"
    assert entry2.issuer_data.public_key == pk

def test_issuer_public_data_revocation_check():
    pk = api.PublicKeyBLS(b"key")
    # "C0" in hex is 11000000 in binary
    data = api.IssuerPublicData(
        issuer_name="Test-Issuer",
        public_key=pk,
        revocation_bitstring="C0",
        valid_until_weeks=1,
        validity_window_days=1
    )
    
    assert data.check_revocation_status("0") is True  # First bit of 'C' (1)
    assert data.check_revocation_status("1") is True  # Second bit of 'C' (1)
    assert data.check_revocation_status("2") is False # Third bit (0)
    assert data.check_revocation_status("7") is False # Last bit of first byte (0)
    
    # Out of bounds
    assert data.check_revocation_status("-1") is False
    assert data.check_revocation_status("8") is False # Start of second byte (doesn't exist)
