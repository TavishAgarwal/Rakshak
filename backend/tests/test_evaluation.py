import pytest
from app.evaluation import compute_ps7_summary, _benchmark_anomaly_metrics

def test_compute_ps7_summary():
    # Should not throw any errors, testing end to end DS metric computation.
    summary = compute_ps7_summary()
    assert summary is not None
    assert "anomaly_detection" in summary
    assert "mitre_attack_attribution" in summary
    
    anomaly = summary["anomaly_detection"]
    assert anomaly["precision"] >= 0.0
    assert anomaly["precision"] <= 1.0
    assert anomaly["recall_detection_rate"] >= 0.0
    assert anomaly["recall_detection_rate"] <= 1.0
    assert anomaly["f1"] >= 0.0
    assert anomaly["f1"] <= 1.0

def test_benchmark_anomaly_metrics_directly():
    overall, manifest = _benchmark_anomaly_metrics()
    assert overall["sample_count"] == 10000
    assert overall["threshold"] == 0.65
    assert len(overall["cases"]) == 10000
    assert overall["true_positive"] > 0
    assert overall["true_negative"] > 0
    assert overall["precision"] > 0
    assert overall["recall_detection_rate"] > 0
    assert overall["false_positive_rate"] >= 0
