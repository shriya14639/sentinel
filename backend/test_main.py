"""Tests for the FastAPI event-processing endpoints."""

import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app


def make_event(system_id="server-1", event_id="api-test-event", cpu_pct=32):
    return {
        "event_id": event_id,
        "timestamp": "2026-10-10T12:00:00Z",
        "system_id": system_id,
        "metrics": {
            "cpu_pct": cpu_pct,
            "memory_pct": 56,
            "network_in_mbps": 90,
            "network_out_mbps": 65,
            "failed_logins": 0,
            "error_rate": 0.8,
        },
    }


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test.db")
        self.db_path_patch = patch.dict(
            os.environ, {"SENTINEL_DB_PATH": self.db_path}
        )
        self.db_path_patch.start()
        self.client = TestClient(app)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    def test_health(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_normal_event_is_saved_without_explanation(self):
        response = self.client.post("/events", json=make_event())

        self.assertEqual(response.status_code, 201)
        result = response.json()
        self.assertFalse(result["is_anomaly"])
        self.assertEqual(result["severity"], "LOW")
        self.assertIsNone(result["explanation"])
        self.assertIsInstance(result["record_id"], int)

        history = self.client.get("/metrics/server-1").json()
        self.assertEqual(history["count"], 1)
        self.assertEqual(history["items"][0]["metrics"]["cpu_pct"], 32)

    def test_anomalous_event_gets_explanation_and_is_listed_as_incident(self):
        explanation = {
            "status": "fallback",
            "source": "rule_based_fallback",
            "advisory_only": True,
        }
        with patch("backend.main.explain_incident", return_value=explanation) as explain:
            response = self.client.post(
                "/events",
                json=make_event(
                    system_id="server-2",
                    event_id="api-test-anomaly",
                    cpu_pct=98,
                ),
            )

        self.assertEqual(response.status_code, 201)
        result = response.json()
        self.assertTrue(result["is_anomaly"])
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertEqual(result["explanation"], explanation)
        explain.assert_called_once()

        incidents = self.client.get(
            "/incidents?severity=MEDIUM&system_id=server-2"
        ).json()
        self.assertEqual(incidents["total"], 1)
        self.assertEqual(
            incidents["items"][0]["event_id"], "api-test-anomaly"
        )

    def test_ground_truth_labels_are_discarded(self):
        event = make_event(cpu_pct=98)
        event["injected_anomaly"] = False
        event["anomaly_type"] = "misleading_label"

        response = self.client.post("/events", json=event)

        self.assertEqual(response.status_code, 201)
        result = response.json()
        self.assertTrue(result["is_anomaly"])
        self.assertNotIn("injected_anomaly", result)
        self.assertNotIn("anomaly_type", result)

    def test_invalid_event_returns_422(self):
        response = self.client.post(
            "/events",
            json={"system_id": "server-1", "metrics": {}},
        )

        self.assertEqual(response.status_code, 422)

    def test_cors_allows_any_origin_and_preflight_method(self):
        response = self.client.options(
            "/events",
            headers={
                "Origin": "https://frontend.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["access-control-allow-origin"], "*"
        )
        self.assertIn(
            "POST", response.headers["access-control-allow-methods"]
        )


if __name__ == "__main__":
    unittest.main()
