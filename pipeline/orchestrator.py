
"""Orchestrate anomaly scoring and severity classification."""

import json

from anomaly_detection.score import score_event
from pipeline.severity import classify_event


def process_event(event: dict) -> dict:
    """Score an event and add its severity and deviated metrics."""

    scored_event = score_event(event)
    return classify_event(scored_event)


def process_events(events: list[dict]) -> list[dict]:
    """Process multiple events through the pipeline."""

    return [process_event(event) for event in events]


def process_stream(events):
    """Process events one at a time from an iterable."""

    for event in events:
        yield process_event(event)


def replay_jsonl_stream(file_path: str):
    """Read and process events from a JSONL file one at a time."""

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                event = json.loads(line)
                yield process_event(event)


def process_replay(replay_events):
    """Process and print events received from a replay stream."""

    for result in process_stream(replay_events):
        print(
            f"{result.get('system_id', 'unknown')} | "
            f"Severity: {result['severity']} | "
            f"Anomaly: {result['is_anomaly']} | "
            f"Score: {result['anomaly_score']}"
        )
        yield result

