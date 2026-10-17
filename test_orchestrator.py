
import json

from pipeline.orchestrator import process_event, process_stream


with open("data/sample_events.json", "r", encoding="utf-8") as file:
    events = json.load(file)

# Test individual event processing.
for event in events:
    result = process_event(event)

    assert "anomaly_score" in result
    assert "is_anomaly" in result
    assert "severity" in result
    assert "deviated_metrics" in result
    assert "correlation_detected" in result

# Test stream processing.
stream_results = list(process_stream(iter(events)))

assert len(stream_results) == len(events)

print(f"All {len(events)} events processed successfully!")
print("Single-event and stream tests passed!")
