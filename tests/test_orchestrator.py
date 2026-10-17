
import unittest

from pipeline.orchestrator import create_detector, process_event
from src.anomaly_detection import METRICS


def make_event(event_id, values, injected_anomaly=False):
    return {
        "event_id": event_id,
        "system_id": "server-1",
        "metrics": dict(zip(METRICS, values)),
        "injected_anomaly": injected_anomaly,
    }


class TestOrchestrator(unittest.TestCase):
    def setUp(self):
        self.training_events = [
            make_event("normal-1", [30, 50, 20, 15, 0, 0.5]),
            make_event("normal-2", [31, 51, 21, 16, 0, 0.6]),
            make_event("normal-3", [29, 49, 19, 14, 1, 0.4]),
            make_event("normal-4", [30, 50, 20, 15, 0, 0.5]),
        ]
        self.detector = create_detector(self.training_events)

    def test_normal_event_gets_low_severity(self):
        event = make_event(
            "normal-test", [30, 50, 20, 15, 0, 0.5]
        )

        result = process_event(event, self.detector)

        self.assertFalse(result["is_anomaly"])
        self.assertEqual(result["severity"], "LOW")
        self.assertEqual(result["deviated_metrics"], [])
        self.assertFalse(result["correlation_detected"])
        self.assertIn("flagged_metrics", result)

    def test_extreme_cpu_spike_is_classified(self):
        event = make_event(
            "cpu-spike", [95, 50, 20, 15, 0, 0.5]
        )

        result = process_event(event, self.detector)

        self.assertTrue(result["is_anomaly"])
        self.assertIn("cpu_pct", result["flagged_metrics"])
        self.assertEqual(result["deviated_metrics"], result["flagged_metrics"])
        self.assertIn(
            result["severity"], {"MEDIUM", "HIGH", "CRITICAL"}
        )
        self.assertIn("anomaly_score", result)
        self.assertIn("metric_scores", result)

    def test_original_event_fields_are_preserved(self):
        event = make_event(
            "preserve-test", [30, 50, 20, 15, 0, 0.5]
        )

        result = process_event(event, self.detector)

        self.assertEqual(result["event_id"], event["event_id"])
        self.assertEqual(result["system_id"], event["system_id"])
        self.assertEqual(result["metrics"], event["metrics"])
        self.assertEqual(
            result["injected_anomaly"], event["injected_anomaly"]
        )


if __name__ == "__main__":
    unittest.main()
