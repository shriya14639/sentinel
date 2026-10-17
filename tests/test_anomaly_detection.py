
import unittest

from src.anomaly_detection import METRICS, RobustAnomalyDetector


def make_event(event_id, values, injected_anomaly=False):
    return {
        "event_id": event_id,
        "system_id": "server-1",
        "metrics": dict(zip(METRICS, values)),
        "injected_anomaly": injected_anomaly,
    }


class TestRobustAnomalyDetector(unittest.TestCase):
    def setUp(self):
        # Simple normal training data with small variations.
        self.training_events = [
            make_event("normal-1", [30, 50, 20, 15, 0, 0.5]),
            make_event("normal-2", [31, 51, 21, 16, 0, 0.6]),
            make_event("normal-3", [29, 49, 19, 14, 1, 0.4]),
            make_event("normal-4", [30, 50, 20, 15, 0, 0.5]),
            # This injected anomaly must not affect the learned baseline.
            make_event("anomaly-1", [99, 99, 99, 99, 20, 9.0], True),
        ]
        self.detector = RobustAnomalyDetector(threshold=6.0)
        self.detector.fit(self.training_events)

    def test_detector_fits_baseline(self):
        self.assertTrue(self.detector.fitted)
        self.assertEqual(set(self.detector.baseline), set(METRICS))

    def test_detects_extreme_cpu_spike(self):
        event = make_event("test-spike", [95, 50, 20, 15, 0, 0.5])
        result = self.detector.predict_one(event)
        self.assertTrue(result["is_anomaly"])
        self.assertIn("cpu_pct", result["flagged_metrics"])

    def test_normal_event_is_not_flagged(self):
        event = make_event("test-normal", [30, 50, 20, 15, 0, 0.5])
        result = self.detector.predict_one(event)
        self.assertFalse(result["is_anomaly"])

    def test_prediction_does_not_require_ground_truth_label(self):
        event = make_event("unlabelled", [95, 50, 20, 15, 0, 0.5])
        del event["injected_anomaly"]
        result = self.detector.predict_one(event)
        self.assertTrue(result["is_anomaly"])

    def test_prediction_contains_scores(self):
        event = make_event("test-score", [95, 50, 20, 15, 0, 0.5])
        result = self.detector.predict_one(event)
        self.assertIn("anomaly_score", result)
        self.assertIn("metric_scores", result)


if __name__ == "__main__":
    unittest.main()
