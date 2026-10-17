
import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).parent / "data" / "simulation")
)

from generator import MetricGenerator
from pipeline.orchestrator import process_stream


ANOMALY_TYPES = [
    "cpu_spike",
    "memory_leak",
    "resource_exhaustion",
]


def test_anomaly(anomaly_type):
    generator = MetricGenerator(
        n_systems=3,
        seed=7,
        realtime=True,
    )

    generator.inject_anomaly(
        "server-2",
        anomaly_type,
        duration=3,
    )

    events = []
    for _ in range(3):
        events.extend(generator.tick())

    results = list(process_stream(events))

    attacks = [
        event for event in results
        if event["system_id"] == "server-2"
        and event["injected_anomaly"]
    ]

    detected = [
        event for event in attacks
        if event["is_anomaly"]
    ]

    print(f"\nAnomaly type: {anomaly_type}")
    print(f"Injected: {len(attacks)} | Detected: {len(detected)}")

    for event in attacks:
        print(
            f"Score: {event['anomaly_score']:.2f} | "
            f"Severity: {event['severity']} | "
            f"Detected: {event['is_anomaly']}"
        )


if __name__ == "__main__":
    for anomaly_type in ANOMALY_TYPES:
        test_anomaly(anomaly_type)
