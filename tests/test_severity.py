
from pipeline.severity import classify_event


def test_normal_event_is_low():
    event = {
        "is_anomaly": False,
        "anomaly_score": 0.5,
        "flagged_metrics": [],
        "metrics": {},
    }

    result = classify_event(event)

    assert result["severity"] == "LOW"
    assert result["deviated_metrics"] == []
    assert result["correlation_detected"] is False


def test_single_deviated_metric_is_medium():
    event = {
        "is_anomaly": True,
        "anomaly_score": 6.5,
        "flagged_metrics": ["cpu_pct"],
        "metrics": {"failed_logins": 0},
    }

    result = classify_event(event)

    assert result["severity"] == "MEDIUM"
    assert result["deviated_metrics"] == ["cpu_pct"]
    assert result["correlation_detected"] is False


def test_multiple_deviated_metrics_are_high():
    event = {
        "is_anomaly": True,
        "anomaly_score": 7.0,
        "flagged_metrics": ["cpu_pct", "memory_pct"],
        "metrics": {"failed_logins": 0},
    }

    result = classify_event(event)

    assert result["severity"] == "HIGH"
    assert result["correlation_detected"] is True


def test_critical_event():
    event = {
        "is_anomaly": True,
        "anomaly_score": 25.0,
        "flagged_metrics": ["cpu_pct", "memory_pct"],
        "metrics": {"failed_logins": 25},
    }

    result = classify_event(event)

    assert result["severity"] == "CRITICAL"
    assert result["correlation_detected"] is True
