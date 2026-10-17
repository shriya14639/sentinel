"""Tests for score_event. Run from the repo root:  python -m pytest anomaly_detection -q

Anomalous events come from Person 1's generator (seeds not used for training or calibration).
The labels are only used to pick which events to test, never passed as a hint to the detector.
"""
import copy
import json
import math
import random

import pytest

from anomaly_detection import sim_data as d
from anomaly_detection.score import METRICS, MODEL_PATH, InvalidEventError, score_event

NORMAL_EVENT = {
    "event_id": "evt_000001", "timestamp": "2026-10-07T09:00:00Z", "system_id": "server-1",
    "metrics": {"cpu_pct": 34.12, "memory_pct": 61.54, "network_in_mbps": 99.47,
                "network_out_mbps": 92.45, "failed_logins": 0, "error_rate": 0.74},
    "injected_anomaly": False, "anomaly_type": None,
}


def anomaly_window(a_type, seed, system="server-2", duration=10):
    """Events of one system while the generator runs an injected anomaly of the given type."""
    gen = d.MetricGenerator(n_systems=5, seed=seed)
    for _ in range(100):                                   # normal warm-up
        gen.tick()
    gen.inject_anomaly(system, a_type, duration)
    window = []
    for _ in range(duration):
        window.extend(e for e in gen.tick() if e["system_id"] == system)
    return window


# ---------- 1. normal behaviour ----------
def test_normal_event_is_not_flagged():
    r = score_event(NORMAL_EVENT)
    assert r["is_anomaly"] is False
    assert r["anomaly_score"] < 1.0


def test_normal_stream_has_few_false_alarms():
    events = d.normal_events([401], ticks=1000)           # 5000 normal events, unseen seed
    flagged = sum(score_event(e)["is_anomaly"] for e in events)
    assert flagged / len(events) < 0.005                  # target is 0.1%; allow 0.5%


# ---------- 2-5. the four anomaly types ----------
@pytest.mark.parametrize("seed", [401, 402, 403])
@pytest.mark.parametrize("a_type", ["cpu_spike", "brute_force", "resource_exhaustion"])
def test_sharp_anomalies_are_flagged_on_every_event(a_type, seed):
    window = anomaly_window(a_type, seed)
    assert all(score_event(e)["is_anomaly"] for e in window)


@pytest.mark.parametrize("seed", [401, 402, 403])
def test_memory_leak_is_caught_early_and_at_the_end(seed):
    flags = [score_event(e)["is_anomaly"] for e in anomaly_window("memory_leak", seed)]
    assert flags[-1] is True                               # the ramp is obvious by the end
    assert flags.index(True) <= 5                          # first flag within 5 ticks (evaluate.py: max delay 5)


def test_worst_metric_matches_the_anomaly():
    cpu = score_event(anomaly_window("cpu_spike", 401)[0])["metric_scores"]
    logins = score_event(anomaly_window("brute_force", 401)[0])["metric_scores"]
    assert max(cpu, key=cpu.get) == "cpu_pct"
    assert max(logins, key=logins.get) == "failed_logins"


# ---------- 6. invalid input ----------
def with_metric(name, value):
    event = copy.deepcopy(NORMAL_EVENT)
    event["metrics"][name] = value
    return event


@pytest.mark.parametrize("bad_event", [
    "not a dict",
    None,
    {},
    {"metrics": "oops"},
    {"metrics": {}},
    with_metric("cpu_pct", "34.1"),
    with_metric("cpu_pct", None),
    with_metric("cpu_pct", float("nan")),
    with_metric("memory_pct", float("inf")),
    with_metric("failed_logins", True),
])
def test_invalid_events_raise_invalid_event_error(bad_event):
    with pytest.raises(InvalidEventError):
        score_event(bad_event)


def test_missing_metric_names_the_metric():
    event = copy.deepcopy(NORMAL_EVENT)
    del event["metrics"]["error_rate"]
    with pytest.raises(InvalidEventError, match="error_rate"):
        score_event(event)


def test_invalid_event_error_is_a_value_error():
    assert issubclass(InvalidEventError, ValueError)


# ---------- 7. multiple systems ----------
def test_unknown_or_missing_system_id_is_fine():
    base = score_event(NORMAL_EVENT)["anomaly_score"]
    other = copy.deepcopy(NORMAL_EVENT)
    other["system_id"] = "server-99"
    assert score_event(other)["anomaly_score"] == base
    del other["system_id"]
    assert score_event(other)["anomaly_score"] == base


def test_order_and_interleaving_across_systems_do_not_matter():
    events = d.labeled_stream(404, ticks=120)             # 5 systems, some anomalous
    in_order = [score_event(e)["anomaly_score"] for e in events]
    shuffled = list(range(len(events)))
    random.Random(0).shuffle(shuffled)
    out_of_order = {i: score_event(events[i])["anomaly_score"] for i in shuffled}
    assert in_order == [out_of_order[i] for i in range(len(events))]


# ---------- 8. repeated inference ----------
def test_repeated_inference_is_identical_and_does_not_change_input():
    event = copy.deepcopy(NORMAL_EVENT)
    before = json.dumps(event, sort_keys=True)
    first = score_event(event)
    for _ in range(500):
        assert score_event(event) == first
    assert json.dumps(event, sort_keys=True) == before


# ---------- ground truth must not matter ----------
def test_labels_are_ignored():
    window = anomaly_window("cpu_spike", 401)
    for event in window:
        labeled = score_event(event)
        stripped = copy.deepcopy(event)
        for key in ("injected_anomaly", "anomaly_type", "system_id", "event_id", "timestamp"):
            stripped.pop(key)
        assert score_event(stripped)["anomaly_score"] == labeled["anomaly_score"]
        lying = copy.deepcopy(event)
        lying["injected_anomaly"], lying["anomaly_type"] = False, None
        assert score_event(lying)["is_anomaly"] == labeled["is_anomaly"]
    liar = copy.deepcopy(NORMAL_EVENT)
    liar["injected_anomaly"], liar["anomaly_type"] = True, "cpu_spike"
    assert score_event(liar)["is_anomaly"] is False


# ---------- output contract ----------
def test_output_contract():
    r = score_event(NORMAL_EVENT)
    for key, value in NORMAL_EVENT.items():                # original fields preserved
        assert r[key] == value
    assert type(r["anomaly_score"]) is float and math.isfinite(r["anomaly_score"])
    assert type(r["is_anomaly"]) is bool
    assert set(r["metric_scores"]) == set(METRICS)
    assert r["anomaly_score"] == max(r["metric_scores"].values())
    assert r["is_anomaly"] == (r["anomaly_score"] >= 1.0)


# ---------- drift guards ----------
def test_metric_names_match_the_generator():
    assert tuple(d.METRICS) == METRICS


def test_model_file_matches_metric_names():
    with open(MODEL_PATH) as f:
        model = json.load(f)
    assert tuple(model["metrics"]) == METRICS