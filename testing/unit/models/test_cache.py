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

def test_cache_check_bit_index():
    from bbs_iss.exceptions.exceptions import IssuerNotFoundInCacheError
    cache = PublicDataCache()
    pk = api.PublicKeyBLS(b"key")
    # "C0" = 11000000
    data = api.IssuerPublicData("Issuer1", pk, "C0", 7, 7)
    cache.update("Issuer1", data)
    
    # Valid checks
    assert cache.check_bit_index("Issuer1", 0) is True
    assert cache.check_bit_index("Issuer1", 1) is True
    assert cache.check_bit_index("Issuer1", 2) is False
    
    # Missing issuer check
    with pytest.raises(IssuerNotFoundInCacheError) as excinfo:
        cache.check_bit_index("UnknownIssuer", 0)
    assert "UnknownIssuer" in str(excinfo.value)
