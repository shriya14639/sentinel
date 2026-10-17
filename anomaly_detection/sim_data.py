"""Data generation for training, calibration and testing.

Uses Person 1's generator unchanged. Every dataset is rebuilt from its seed, so
nothing needs to be saved to disk and results are reproducible.
"""
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "data" / "simulation"))

from generator import ANOMALY_TYPES, METRICS, MetricGenerator  # noqa: E402

N_SYSTEMS = 5
TRAIN_SEEDS = [101, 102, 103, 104]      # fit the centers
CAL_SEEDS = list(range(201, 211))       # set the limits
TEST_SEEDS = list(range(301, 311))      # final evaluation, with injected anomalies
NORMAL_TICKS = 2000
TEST_TICKS = 1500
# Not used anywhere above: seed 42 (sample_events.json) and seed 7 (replay.py default).


def normal_events(seeds, ticks=NORMAL_TICKS, n_systems=N_SYSTEMS):
    """Normal-only events. We never call inject_anomaly, so no anomalies can exist."""
    events = []
    for seed in seeds:
        gen = MetricGenerator(n_systems=n_systems, seed=seed)
        for _ in range(ticks):
            events.extend(gen.tick())
    assert not any(e["injected_anomaly"] for e in events), "anomaly found in normal data"
    return events


def labeled_stream(seed, ticks=TEST_TICKS, n_systems=N_SYSTEMS, gap=40):
    """Stream with injected anomalies for validation.

    Every `gap` ticks (from tick 60) one anomaly is injected on a random system.
    Types cycle through ANOMALY_TYPES; durations are chosen from 4, 6, 8, 10 ticks.
    """
    gen = MetricGenerator(n_systems=n_systems, seed=seed)
    rng = np.random.default_rng(seed + 999)   # separate RNG: choices don't touch the generator's
    events, k = [], 0
    for t in range(ticks):
        if t >= 60 and t % gap == 0:
            system_id = f"server-{rng.integers(1, n_systems + 1)}"
            if gen.systems[system_id].anomaly is None:   # never overlap two anomalies on one system
                duration = int(rng.choice([4, 6, 8, 10]))
                gen.inject_anomaly(system_id, ANOMALY_TYPES[k % len(ANOMALY_TYPES)], duration)
            k += 1
        events.extend(gen.tick())
    return events


def to_matrix(events):
    """Events -> array of shape (n_events, 6), columns in METRICS order. Labels are NOT included."""
    return np.array([[e["metrics"][m] for m in METRICS] for e in events], dtype=float)