"""Sentinel anomaly detector: inference only.

    from anomaly_detection.score import score_event
    result = score_event(event)       # result["anomaly_score"], result["is_anomaly"]

Reads only the six numbers in event["metrics"]. It never looks at injected_anomaly,
anomaly_type, system_id or timestamp. Stateless: the same event always gives the same result.
"""
import copy
import json
import math
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent / "model.json"

# Same names and order as Person 1's generator. test_score.py checks they still match.
METRICS = ("cpu_pct", "memory_pct", "network_in_mbps",
           "network_out_mbps", "failed_logins", "error_rate")
THRESHOLD = 1.0   # is_anomaly means anomaly_score >= THRESHOLD

_model = None     # loaded once, on first use


class InvalidEventError(ValueError):
    """The event is missing a metric, or a metric is not a finite number."""


def _load_model():
    global _model
    if _model is None:
        with open(MODEL_PATH) as f:
            model = json.load(f)
        if model.get("format_version") != 1:
            raise RuntimeError(f"unsupported model format in {MODEL_PATH}")
        if tuple(model["metrics"]) != METRICS:
            raise RuntimeError("model.json metrics do not match score.py METRICS")
        for m in METRICS:
            if not (math.isfinite(model["centers"][m]) and math.isfinite(model["limits"][m])
                    and model["limits"][m] > 0):
                raise RuntimeError(f"invalid parameters for {m} in {MODEL_PATH}")
        _model = model
    return _model


def _metric_value(event, metric):
    try:
        value = event["metrics"][metric]
    except (KeyError, TypeError):
        raise InvalidEventError(f"missing metric: {metric}") from None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidEventError(f"{metric} must be a number, got {value!r}")
    if not math.isfinite(value):
        raise InvalidEventError(f"{metric} must be finite, got {value!r}")
    return float(value)


def score_event(event):
    """Score one event. Returns a copy of the event plus three fields:

    anomaly_score  float  max over metrics of |value - center| / limit. Higher = more anomalous.
                          1.0 is the edge of normal; 2.0 means twice the normal limit.
    is_anomaly     bool   anomaly_score >= 1.0
    metric_scores  dict   the same ratio for each of the six metrics

    Raises InvalidEventError if the event is not a dict or a metric is missing/not a finite number.
    """
    if not isinstance(event, dict):
        raise InvalidEventError("event must be a dict")
    model = _load_model()
    metric_scores = {}
    for m in METRICS:
        value = _metric_value(event, m)
        metric_scores[m] = abs(value - model["centers"][m]) / model["limits"][m]
    score = max(metric_scores.values())

    result = copy.deepcopy(event)          # never modify the caller's event
    result["anomaly_score"] = score
    result["is_anomaly"] = bool(score >= THRESHOLD)
    result["metric_scores"] = metric_scores
    return result