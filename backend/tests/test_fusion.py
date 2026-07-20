import pytest
from app.fusion.dempster_shafer import ds_combine, to_bpa, fuse_scores

def test_ds_combine_full_conflict():
    # K=1 means Malicious and Benign completely contradict
    # BPA 1: 100% Malicious
    bpa1 = {"Malicious": 1.0, "Benign": 0.0, "Uncertain": 0.0}
    # BPA 2: 100% Benign
    bpa2 = {"Malicious": 0.0, "Benign": 1.0, "Uncertain": 0.0}
    
    # Should handle K=1 gracefully and return Uncertain
    combined = ds_combine([bpa1, bpa2])
    assert combined["conflict"] == 1.0
    assert combined["Uncertain"] == 1.0
    assert combined["Malicious"] == 0.0
    assert combined["Benign"] == 0.0

def test_ds_fuse_zero_evidence():
    result = fuse_scores([])
    assert result.belief == 0.0
    assert result.plausibility == 1.0
    assert result.uncertainty == 1.0
    assert result.conflict == 0.0

def test_ds_fuse_single_high_confidence():
    result = fuse_scores([("network", 0.9)], default_reliability=0.8)
    assert result.belief == 0.72  # 0.9 * 0.8
    assert result.conflict == 0.0

def test_ds_fuse_contradicting_high_confidence():
    # Two sources: one says 0.9 (malicious), other says 0.1 (benign)
    bpa1 = to_bpa(0.9, 0.8) # high malicious
    bpa2 = to_bpa(0.1, 0.8) # high benign
    
    combined = ds_combine([bpa1, bpa2])
    assert combined["conflict"] > 0.0
    assert combined["conflict"] < 1.0
    
    assert "Malicious" in combined
    assert "Benign" in combined
