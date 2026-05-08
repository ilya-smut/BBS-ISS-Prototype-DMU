import pytest
from bbs_iss.entities.issuer import IssuerInstance
from bbs_iss.entities.holder import HolderInstance
import bbs_iss.interfaces.requests_api as api
from bbs_iss.exceptions.exceptions import IssuerNotAvailable, ProofValidityError
from unittest.mock import patch
from datetime import datetime, timezone

def test_issuer_rejects_overlapping_sessions():
    """Assert IssuerNotAvailable is raised if an ISSUANCE request arrives while busy."""
    issuer = IssuerInstance()
    holder1 = HolderInstance()
    holder2 = HolderInstance()
    
    attr = api.IssuanceAttributes()
    attr.append("test", "test", api.AttributeType.REVEALED)
    attr.append("secret", "test", api.AttributeType.HIDDEN)
    
    issuer_name = "Mock-Issuer"
    data = api.IssuerPublicData(issuer_name, issuer.public_key, "0"*10, 52, 7)
    holder1.public_data_cache.update(issuer_name, data)
    holder2.public_data_cache.update(issuer_name, data)
    
    req1 = holder1.issuance_request(issuer_name, attr, "c1")
    req2 = holder2.issuance_request(issuer_name, attr, "c2")
    
    # First request succeeds and makes issuer busy
    issuer.process_request(req1)
    
    # Second request should fail
    with pytest.raises(IssuerNotAvailable):
        issuer.process_request(req2)

def test_issuer_rejects_replayed_proof():
    """Assert ProofValidityError is raised when a valid proof from a different session (different nonce) is replayed."""
    issuer = IssuerInstance()
    
    # Session 1
    holder1 = HolderInstance()
    attr1 = api.IssuanceAttributes()
    attr1.append("secret", "test", api.AttributeType.HIDDEN)
    attr1.append("test", "test", api.AttributeType.REVEALED)
    
    issuer_name = "Issuer1"
    data1 = api.IssuerPublicData(issuer_name, issuer.public_key, "0"*10, 52, 7)
    holder1.public_data_cache.update(issuer_name, data1)
    
    req1 = holder1.issuance_request(issuer_name, attr1, "c1")
    freshness1 = issuer.process_request(req1)
    valid_blind_req1 = holder1.process_request(freshness1)
    
    issuer2 = IssuerInstance()
    holder2 = HolderInstance()
    attr2 = api.IssuanceAttributes()
    attr2.append("test", "tampered", api.AttributeType.HIDDEN)
    issuer_name2 = "Issuer2"
    data2 = api.IssuerPublicData(issuer_name2, issuer2.public_key, "0"*10, 52, 7)
    holder2.public_data_cache.update(issuer_name2, data2)
    req2 = holder2.issuance_request(issuer_name2, attr2, "c2")
    freshness2 = issuer2.process_request(req2)
    valid_blind_req2 = holder2.process_request(freshness2)

    # Tamper with Session 1's request by injecting Session 2's perfectly well-formed,
    # but cryptographically mismatched proof.
    import copy
    invalid_blind_req = copy.copy(valid_blind_req1)
    invalid_blind_req.proof = valid_blind_req2.proof
    
    with pytest.raises(ProofValidityError):
        issuer.process_request(invalid_blind_req)

@patch('bbs_iss.entities.issuer.datetime')
def test_epoch_boundary_initial_issuance_outside_window(mock_datetime):
    issuer = IssuerInstance()
    issuer.set_epoch_size_days(7)
    issuer.set_re_issuance_window_days(2)
    issuer.set_baseline_date("2026-01-01T00:00:00Z")
    
    mock_now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    mock_datetime.now.return_value = mock_now
    mock_datetime.fromisoformat = datetime.fromisoformat
    
    expiry = issuer.generate_valid_until()
    assert expiry == "2026-01-08T00:00:00Z"

@patch('bbs_iss.entities.issuer.datetime')
def test_epoch_boundary_initial_issuance_inside_window(mock_datetime):
    issuer = IssuerInstance()
    issuer.set_epoch_size_days(7)
    issuer.set_re_issuance_window_days(2)
    issuer.set_baseline_date("2026-01-01T00:00:00Z")
    
    # 2 days before boundary
    mock_now = datetime(2026, 1, 6, tzinfo=timezone.utc)
    mock_datetime.now.return_value = mock_now
    mock_datetime.fromisoformat = datetime.fromisoformat
    
    expiry = issuer.generate_valid_until()
    assert expiry == "2026-01-15T00:00:00Z"

@patch('bbs_iss.entities.issuer.datetime')
def test_epoch_boundary_before_baseline(mock_datetime):
    issuer = IssuerInstance()
    issuer.set_epoch_size_days(7)
    issuer.set_re_issuance_window_days(2)
    issuer.set_baseline_date("2026-01-01T00:00:00Z")
    
    # 7 days before baseline
    mock_now = datetime(2025, 12, 25, tzinfo=timezone.utc)
    mock_datetime.now.return_value = mock_now
    mock_datetime.fromisoformat = datetime.fromisoformat
    
    expiry = issuer.generate_valid_until()
    assert expiry == "2026-01-08T00:00:00Z"

@patch('bbs_iss.entities.issuer.datetime')
def test_epoch_boundary_late_issuance(mock_datetime):
    issuer = IssuerInstance()
    issuer.set_epoch_size_days(7)
    issuer.set_re_issuance_window_days(2)
    issuer.set_baseline_date("2026-01-01T00:00:00Z")
    
    # Late issuance, not in window
    mock_now = datetime(2026, 2, 2, tzinfo=timezone.utc)
    mock_datetime.now.return_value = mock_now
    mock_datetime.fromisoformat = datetime.fromisoformat
    
    # Epochs: Jan 1 -> Jan 8 -> Jan 15 -> Jan 22 -> Jan 29 -> Feb 5
    expiry = issuer.generate_valid_until()
    assert expiry == "2026-02-05T00:00:00Z"

@patch('bbs_iss.entities.issuer.datetime')
def test_epoch_boundary_late_issuance_inside_window(mock_datetime):
    issuer = IssuerInstance()
    issuer.set_epoch_size_days(7)
    issuer.set_re_issuance_window_days(2)
    issuer.set_baseline_date("2026-01-01T00:00:00Z")
    
    # Late issuance, in window
    mock_now = datetime(2026, 2, 4, tzinfo=timezone.utc)
    mock_datetime.now.return_value = mock_now
    mock_datetime.fromisoformat = datetime.fromisoformat
    
    # Epochs: Feb 5. Since Feb 4 is 1 day before Feb 5, it should bump to Feb 12
    expiry = issuer.generate_valid_until()
    assert expiry == "2026-02-12T00:00:00Z"
