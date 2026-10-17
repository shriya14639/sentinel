
from pipeline.severity import classify_event


def make_event(anomaly, score, metrics, metric_scores):
    return {
        "is_anomaly": anomaly,
        "anomaly_score": score,
        "metrics": metrics,
        "metric_scores": metric_scores,
    }


normal = make_event(False, 0.5, {"failed_logins": 0}, {})
assert classify_event(normal)["severity"] == "LOW"

small = make_event(
    True, 1.31, {"failed_logins": 0},
    {"memory_pct": 1.31}
)
assert classify_event(small)["severity"] == "MEDIUM"

multiple = make_event(
    True, 1.6, {"failed_logins": 0},
    {"cpu_pct": 1.2, "memory_pct": 1.4}
)
result = classify_event(multiple)
assert result["correlation_detected"] is True

critical = make_event(
    True, 3.4, {"failed_logins": 25},
    {"failed_logins": 3.4, "cpu_pct": 1.5}
)
assert classify_event(critical)["severity"] == "CRITICAL"

print("All 4 severity rule tests passed!")
