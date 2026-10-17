

"""Severity classification for Sentinel events."""

METRIC_THRESHOLD = 1.0
MULTIVARIATE_THRESHOLD = 2


def classify_event(event: dict) -> dict:
    """Add deviated metrics, correlation signal, and severity."""

    result = event.copy()

    # Use the detector's flagged metrics for consistent classification.
    deviated_metrics = result.get("flagged_metrics", [])
    result["deviated_metrics"] = list(deviated_metrics)

    # Keep the existing multivariate signal, if present.
    result["correlation_signal"] = (
        result.get("anomaly_score", 0) >= MULTIVARIATE_THRESHOLD
    )

    if result["correlation_signal"]:
        result["severity"] = "high"
    elif result["deviated_metrics"]:
        result["severity"] = "medium"
    else:
        result["severity"] = "low"

    return result
