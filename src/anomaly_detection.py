
"""Robust statistical anomaly detector for system metrics."""

from statistics import median

METRICS = (
    "cpu_pct",
    "memory_pct",
    "network_in_mbps",
    "network_out_mbps",
    "failed_logins",
    "error_rate",
)

SCALE_FLOORS = {
    "cpu_pct": 1.0,
    "memory_pct": 1.0,
    "network_in_mbps": 1.0,
    "network_out_mbps": 1.0,
    "failed_logins": 1.0,
    "error_rate": 0.05,
}


class RobustAnomalyDetector:
    """Detect unusual metric values using a fitted normal baseline."""

    def __init__(self, threshold=6.0):
        if threshold <= 0:
            raise ValueError("threshold must be positive")

        self.threshold = threshold
        self.baseline = {}
        self.scales = {}
        self.fitted = False

    def fit(self, events):
        """Learn baselines from normal events only."""
        events = list(events)
        if not events:
            raise ValueError("At least one training event is required")

        values = {metric: [] for metric in METRICS}

        for event in events:
            # Exclude injected anomalies from training when labels are available.
            if event.get("injected_anomaly", False):
                continue

            metrics = event.get("metrics", {})
            for metric in METRICS:
                value = metrics.get(metric)
                if value is None:
                    continue
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(f"{metric} must be numeric")
                values[metric].append(float(value))

        for metric, samples in values.items():
            if not samples:
                raise ValueError(f"No normal training values for {metric}")

            center = median(samples)
            mad = median(abs(value - center) for value in samples)
            robust_scale = max(1.4826 * mad, SCALE_FLOORS[metric])

            self.baseline[metric] = center
            self.scales[metric] = robust_scale

        self.fitted = True
        return self

    def predict_one(self, event):
        """Predict whether one event contains an anomalous metric."""
        if not self.fitted:
            raise RuntimeError("Call fit() before predict_one()")

        metrics = event.get("metrics", {})
        scores = {}

        for metric in METRICS:
            if metric not in metrics:
                raise ValueError(f"Missing metric: {metric}")

            value = metrics[metric]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{metric} must be numeric")

            scores[metric] = (
                abs(float(value) - self.baseline[metric])
                / self.scales[metric]
            )

        flagged = [
            metric for metric, score in scores.items()
            if score >= self.threshold
        ]

        return {
            "event_id": event.get("event_id"),
            "system_id": event.get("system_id"),
            "is_anomaly": bool(flagged),
            "anomaly_score": round(max(scores.values()), 3),
            "flagged_metrics": flagged,
            "metric_scores": {
                metric: round(score, 3)
                for metric, score in scores.items()
            },
        }
