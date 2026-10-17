"""Tests for Part 4. They use mocks: no real API, key or network is needed.

Run from the repo root:  python -m unittest genai_explanation.test_explain -v
"""
import json
import os
import socket
import unittest
import urllib.error
from unittest import mock

from genai_explanation import explain
from genai_explanation.explain import explain_incident, LLMError

EXPECTED_KEYS = {"event_id", "status", "llm_used", "source", "incident_type", "severity", "summary",
                 "evidence", "recommended_actions", "warnings", "error", "advisory_only"}
FAKE_ENV = {"SENTINEL_LLM_API_KEY": "test-key-not-real",
            "SENTINEL_LLM_BASE_URL": "https://llm.example.invalid/v1",
            "SENTINEL_LLM_MODEL": "test-model"}
NORMAL = {"cpu_pct": 35.0, "memory_pct": 52.0, "network_in_mbps": 20.0,
          "network_out_mbps": 15.0, "failed_logins": 1.0, "error_rate": 0.01}
NORMAL_SCORES = {"cpu_pct": 0.2, "memory_pct": 0.1, "network_in_mbps": 0.3,
                 "network_out_mbps": 0.2, "failed_logins": 0.1, "error_rate": 0.1}

VALID_LLM_JSON = json.dumps({
    "incident_type": "possible_brute_force_activity",
    "summary": "Failed logins are far above the normal range, which may indicate "
               "brute-force activity. This is a hypothesis, not a confirmed cause.",
    "recommended_actions": ["Review authentication logs for the affected system.",
                            "Check whether the failures come from one source or many."],
})


def make_event(metric_changes, score_changes, **extra):
    metrics, scores = dict(NORMAL), dict(NORMAL_SCORES)
    metrics.update(metric_changes)
    scores.update(score_changes)
    event = {"system_id": "srv-01", "timestamp": "2026-10-09T10:00:00Z",
             "metrics": metrics, "metric_scores": scores,
             "anomaly_score": max(scores.values()), "is_anomaly": True}
    event.update(extra)
    return event


def scenario_a():   # critical, failed logins far above normal
    return make_event({"failed_logins": 85.0}, {"failed_logins": 7.5}, severity="critical")


def scenario_b():   # high, CPU and inbound traffic unusual
    return make_event({"cpu_pct": 97.0, "network_in_mbps": 900.0},
                      {"cpu_pct": 5.1, "network_in_mbps": 6.0}, severity="high")


def check_schema(test, result):
    test.assertEqual(set(result), EXPECTED_KEYS)
    test.assertIsInstance(result["status"], str)
    test.assertIsInstance(result["llm_used"], bool)
    test.assertIsInstance(result["incident_type"], str)
    test.assertIsInstance(result["severity"], str)
    test.assertIsInstance(result["summary"], str)
    test.assertIsInstance(result["evidence"], list)
    test.assertIsInstance(result["recommended_actions"], list)
    test.assertIsInstance(result["warnings"], list)
    test.assertTrue(result["advisory_only"])


class FallbackScenarios(unittest.TestCase):
    """No API key set: the rule-based fallback must work."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_scenario_a_brute_force(self):
        r = explain_incident(scenario_a())
        check_schema(self, r)
        self.assertEqual(r["status"], "fallback")
        self.assertFalse(r["llm_used"])
        self.assertEqual(r["incident_type"], "possible_brute_force_activity")
        self.assertEqual(r["severity"], "CRITICAL")
        self.assertTrue(any("failed_logins" in line for line in r["evidence"]))
        self.assertIn("not an LLM analysis", r["summary"])

    def test_scenario_b_resource_and_network(self):
        r = explain_incident(scenario_b())
        check_schema(self, r)
        self.assertEqual(r["incident_type"], "unusual_resource_and_network_activity")
        self.assertEqual(r["severity"], "HIGH")
        self.assertTrue(any("cpu_pct" in line for line in r["evidence"]))
        self.assertTrue(any("network_in_mbps" in line for line in r["evidence"]))

    def test_missing_api_key_is_reported(self):
        r = explain_incident(scenario_a())
        self.assertTrue(any("SENTINEL_LLM_API_KEY" in w for w in r["warnings"]))

    def test_missing_model_variable_is_reported(self):
        env = dict(FAKE_ENV)
        del env["SENTINEL_LLM_MODEL"]
        with mock.patch.dict(os.environ, env, clear=True):
            r = explain_incident(scenario_a())
        self.assertEqual(r["status"], "fallback")
        self.assertTrue(any("SENTINEL_LLM_MODEL" in w for w in r["warnings"]))

    def test_no_invented_evidence(self):
        r = explain_incident(scenario_a())
        text = " ".join(r["evidence"])
        self.assertNotIn("IP", text)
        self.assertNotIn("user", text.lower())

    def test_missing_severity_and_score_scores(self):
        event = {"metrics": dict(NORMAL)}          # no metric_scores, no severity
        r = explain_incident(event)
        check_schema(self, r)
        self.assertEqual(r["severity"], "UNKNOWN")
        self.assertEqual(r["incident_type"], "unknown_anomaly")
        self.assertTrue(any("not specified" in line for line in r["evidence"]))


class InvalidInput(unittest.TestCase):
    """Scenario C: incomplete or malformed events must not crash."""

    def test_bad_events_return_error_result(self):
        bad_events = [None, "text", 42, [], {}, {"metrics": "nope"}, {"metrics": {}},
                      {"metrics": {"cpu_pct": float("nan")}},
                      {"metrics": {"cpu_pct": True}},
                      {"metrics": {"cpu_pct": "high"}}]
        for bad in bad_events:
            with self.subTest(event=repr(bad)):
                r = explain_incident(bad)
                check_schema(self, r)
                self.assertEqual(r["status"], "error")
                self.assertFalse(r["llm_used"])
                self.assertIsInstance(r["error"], str)

    def test_one_bad_metric_is_skipped_with_warning(self):
        event = scenario_a()
        event["metrics"]["cpu_pct"] = float("nan")
        with mock.patch.dict(os.environ, {}, clear=True):
            r = explain_incident(event)
        self.assertEqual(r["status"], "fallback")
        self.assertTrue(any("cpu_pct" in w for w in r["warnings"]))

    def test_text_is_cleaned_and_shortened(self):
        event = scenario_a()
        event["system_id"] = "srv\n\x00-01 " + "x" * 300
        clean, _ = explain.validate_event(event)
        self.assertLessEqual(len(clean["system_id"]), explain.MAX_ID_LEN)
        self.assertNotIn("\n", clean["system_id"])


class LLMPath(unittest.TestCase):
    """The LLM is mocked. These tests do not touch the network."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, FAKE_ENV, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_valid_llm_output(self):
        with mock.patch.object(explain, "_call_llm", return_value=VALID_LLM_JSON):
            r = explain_incident(scenario_a())
        check_schema(self, r)
        self.assertEqual(r["status"], "ok")
        self.assertTrue(r["llm_used"])
        self.assertEqual(r["source"], "llm")
        self.assertEqual(r["incident_type"], "possible_brute_force_activity")
        self.assertEqual(len(r["recommended_actions"]), 2)

    def test_json_inside_code_fence_is_accepted(self):
        fenced = "```json\n" + VALID_LLM_JSON + "\n```"
        with mock.patch.object(explain, "_call_llm", return_value=fenced):
            self.assertEqual(explain_incident(scenario_a())["status"], "ok")

    def test_llm_unavailable_falls_back(self):
        with mock.patch.object(explain, "_call_llm", side_effect=LLMError("down")):
            r = explain_incident(scenario_a())
        check_schema(self, r)
        self.assertEqual(r["status"], "fallback")
        self.assertFalse(r["llm_used"])
        self.assertTrue(any("LLM explanation failed" in w for w in r["warnings"]))

    def test_malformed_llm_outputs_fall_back(self):
        bad_outputs = [
            "this is not json at all",
            "{ broken json",
            "[1, 2, 3]",
            json.dumps({"incident_type": "alien_invasion", "summary": "x",
                        "recommended_actions": ["y"]}),
            json.dumps({"incident_type": "unknown_anomaly", "summary": "",
                        "recommended_actions": ["y"]}),
            json.dumps({"incident_type": "unknown_anomaly", "summary": "ok",
                        "recommended_actions": "not a list"}),
            json.dumps({"incident_type": "possible_brute_force_activity",
                        "summary": "This is definitely a cyberattack.",
                        "recommended_actions": ["Review logs."]}),
        ]
        for reply in bad_outputs:
            with self.subTest(reply=reply[:40]):
                with mock.patch.object(explain, "_call_llm", return_value=reply):
                    r = explain_incident(scenario_a())
                self.assertEqual(r["status"], "fallback")
                self.assertFalse(r["llm_used"])

    def test_labels_and_unknown_fields_are_not_sent(self):
        event = scenario_a()
        event.update({"injected_anomaly": True, "anomaly_type": "secret_label",
                      "ip_address": "10.9.9.9", "password": "hunter2"})
        sent = {}

        def fake_call(config, system_prompt, user_prompt):
            sent["prompt"] = user_prompt
            return VALID_LLM_JSON

        with mock.patch.object(explain, "_call_llm", side_effect=fake_call):
            explain_incident(event)
        for secret in ("injected_anomaly", "secret_label", "10.9.9.9", "hunter2"):
            self.assertNotIn(secret, sent["prompt"])
        self.assertIn("failed_logins", sent["prompt"])


class CallLLMErrors(unittest.TestCase):
    """_call_llm turns network problems into LLMError (urlopen is mocked)."""
    CONFIG = {"api_key": "k", "base_url": "https://x.invalid/v1", "model": "m", "timeout": 1}

    def _run(self, side_effect):
        with mock.patch.object(explain.urllib.request, "urlopen", side_effect=side_effect):
            with self.assertRaises(LLMError) as ctx:
                explain._call_llm(self.CONFIG, "system", "user")
        return str(ctx.exception)

    def test_timeout(self):
        self._run(socket.timeout())

    def test_network_error(self):
        self._run(urllib.error.URLError("no network"))

    def test_http_error_does_not_leak_key(self):
        err = urllib.error.HTTPError("https://x.invalid", 401, "Unauthorized", {}, None)
        message = self._run(err)
        self.assertIn("401", message)
        self.assertNotIn(self.CONFIG["api_key"] + "x", message)

class IntegrationWithPipeline(unittest.TestCase):
    """Real pipeline (Part 2 scoring + Part 3 severity) -> explain_incident (Part 4)."""

    def test_pipeline_event_can_be_explained(self):
        try:
            from pipeline.orchestrator import process_event
        except (ImportError, TypeError):
            self.skipTest("pipeline package not importable here")
        raw = {"event_id": "evt_test", "timestamp": "2026-10-07T09:00:00Z",
               "system_id": "server-1",
               "metrics": {"cpu_pct": 35.89, "memory_pct": 55.14, "network_in_mbps": 114.58,
                           "network_out_mbps": 86.65, "failed_logins": 10000,
                           "error_rate": 0.79},
               "injected_anomaly": True, "anomaly_type": "brute_force"}
        with mock.patch.dict(os.environ, {}, clear=True):
            r = explain_incident(process_event(raw))
        check_schema(self, r)
        self.assertEqual(r["event_id"], "evt_test")
        self.assertEqual(r["incident_type"], "possible_brute_force_activity")
        self.assertIn(r["severity"], ("MEDIUM", "HIGH", "CRITICAL"))
        self.assertTrue(any("failed_logins" in line for line in r["evidence"]))
        
if __name__ == "__main__":
    unittest.main()