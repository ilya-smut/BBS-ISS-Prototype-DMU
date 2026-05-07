import pytest
from bbs_iss.utils.cache import PublicDataCache
import bbs_iss.interfaces.requests_api as api
from datetime import datetime, timezone

def test_cache_update_and_get():
    cache = PublicDataCache()
    pk = api.PublicKeyBLS(b"key")
    data = api.IssuerPublicData("Issuer1", pk, "0", 7, 7)
    
    # Miss
    assert cache.get("Issuer1") is None
    
    # Update
    cache.update("Issuer1", data)
    
    # Hit
    retrieved = cache.get("Issuer1")
    assert retrieved == data
    
    # Entry check
    entry = cache.get_entry("Issuer1")
    assert entry.issuer_data == data
    assert "Z" in entry.obtained_at # ISO format check

def test_cache_clear():
    cache = PublicDataCache()
    cache.update("I1", api.IssuerPublicData("I1", api.PublicKeyBLS(b"k"), "0", 1, 1))
    assert cache.get("I1") is not None
    
    cache.clear()
    assert cache.get("I1") is None

def test_cache_info_formatting():
    cache = PublicDataCache()
    # Empty state
    info_empty = cache.get_cache_info()
    assert "empty" in info_empty.lower()
    
    # Populated state
    data = api.IssuerPublicData("Mock", api.PublicKeyBLS(b"0"*32), "00", 7, 7)
    cache.update("Mock", data)
    info = cache.get_cache_info()
    
    assert "Mock" in info
    assert "Obtained At" in info
    assert "Public Key" in info
    assert "Revocation" in info
