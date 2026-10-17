

"""Orchestrate anomaly detection and severity classification."""

import json
from pathlib import Path
from collections import defaultdict, deque

from pipeline.severity import classify_event
from src.anomaly_detection import RobustAnomalyDetector


MEMORY_HISTORY_SIZE = 4
MEMORY_TREND_INCREASE = 10.0


def create_detector(training_events):
    """Fit the detector using normal training events."""
    detector = RobustAnomalyDetector()
    detector.fit(training_events)
    return detector


class MemoryTrendTracker:
    """Detect steadily increasing memory usage per system."""

    def __init__(self):
        self.history = defaultdict(
            lambda: deque(maxlen=MEMORY_HISTORY_SIZE)
        )

    def check(self, event):
        system_id = event.get("system_id", "unknown")
        metrics = event.get("metrics", {})
        memory = metrics.get("memory_pct")

        if not isinstance(memory, (int, float)) or isinstance(memory, bool):
            return False

        readings = self.history[system_id]
        readings.append(float(memory))

        if len(readings) < MEMORY_HISTORY_SIZE:
            return False

        steadily_increasing = all(
            readings[i] > readings[i - 1]
            for i in range(1, len(readings))
        )
        large_increase = (
            readings[-1] - readings[0] >= MEMORY_TREND_INCREASE
        )

        return steadily_increasing and large_increase


def process_event(event, detector, trend_tracker=None):
    """Detect anomalies, memory trends, and classify severity."""
    prediction = detector.predict_one(event)

    result = event.copy()
    result.update(prediction)
    result["metrics"] = event.get("metrics", {})

    trend_detected = (
        trend_tracker.check(event)
        if trend_tracker is not None
        else False
    )
    result["memory_trend_detected"] = trend_detected

    if trend_detected:
        result["is_anomaly"] = True
        result["anomaly_score"] = max(
            result.get("anomaly_score", 0),
            6.0,
        )

        flagged = list(result.get("flagged_metrics", []))
        if "memory_pct" not in flagged:
            flagged.append("memory_pct")
        result["flagged_metrics"] = flagged

        scores = dict(result.get("metric_scores", {}))
        scores["memory_pct"] = max(scores.get("memory_pct", 0), 6.0)
        result["metric_scores"] = scores

    return classify_event(result)


def process_events(events, detector):
    """Process a collection of events with memory-trend tracking."""
    tracker = MemoryTrendTracker()
    return [
        process_event(event, detector, tracker)
        for event in events
    ]


def process_stream(events, detector):
    """Process events one at a time with memory-trend tracking."""
    tracker = MemoryTrendTracker()
    for event in events:
        yield process_event(event, detector, tracker)


def replay_jsonl_stream(file_path, detector):
    """Read and process events from a JSONL file."""
    tracker = MemoryTrendTracker()
    with Path(file_path).open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                event = json.loads(line)
                yield process_event(event, detector, tracker)


def process_replay(replay_events, detector):
    """Process and return events received from a replay stream."""
    return list(process_stream(replay_events, detector))
