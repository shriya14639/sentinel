"""Fit the Sentinel anomaly detector and save it to model.json.

Run from the repo root:   python anomaly_detection/train.py [--alpha 0.001]

  centers : median of each metric on the TRAIN set (normal events only)
  limits  : per-metric deviation limit set on a separate CALIBRATION set (normal only),
            so that each metric alone causes at most alpha/6 false alarms
"""
import argparse
import json
from pathlib import Path

import numpy as np

import sim_data as d

MODEL_PATH = Path(__file__).resolve().parent / "model.json"
DEFAULT_ALPHA = 0.001   # target share of normal events wrongly flagged (all metrics together)

# Smallest deviation we would ever call meaningful, per metric. Only used as a safety floor.
FLOORS = {"cpu_pct": 1.0, "memory_pct": 1.0, "network_in_mbps": 1.0,
          "network_out_mbps": 1.0, "failed_logins": 1.0, "error_rate": 0.05}


def calibrated_limit(deviations, budget):
    """Smallest observed deviation v such that the share of events with deviation >= v is <= budget.

    Using observed values (not interpolated quantiles) handles integer metrics like failed_logins.
    If even the largest deviation is more common than the budget, return a value just above it.
    """
    values, counts = np.unique(deviations, return_counts=True)        # ascending values
    share_at_or_above = counts[::-1].cumsum()[::-1] / len(deviations)
    ok = np.where(share_at_or_above <= budget)[0]
    if len(ok) == 0:
        return float(np.nextafter(values[-1], np.inf))
    return float(values[ok[0]])


def fit(train_events, cal_events, alpha):
    x_train = d.to_matrix(train_events)
    x_cal = d.to_matrix(cal_events)
    for name, x in (("train", x_train), ("calibration", x_cal)):
        if not np.isfinite(x).all():
            raise ValueError(f"{name} data contains NaN or infinite values")
    n_budget = len(d.METRICS)
    min_rows = int(10 * n_budget / alpha)
    if len(x_cal) < min_rows:
        raise ValueError(f"alpha={alpha} needs at least {min_rows} calibration rows, got {len(x_cal)}")

    centers = np.median(x_train, axis=0)
    deviations = np.abs(x_cal - centers)
    budget = alpha / n_budget
    limits = [max(calibrated_limit(deviations[:, i], budget), FLOORS[m])
              for i, m in enumerate(d.METRICS)]
    if not all(np.isfinite(limits)) or not all(l > 0 for l in limits):
        raise ValueError(f"invalid limits: {limits}")

    model = {
        "format_version": 1,
        "metrics": list(d.METRICS),
        "centers": {m: float(c) for m, c in zip(d.METRICS, centers)},
        "limits": {m: float(l) for m, l in zip(d.METRICS, limits)},
        "floors": FLOORS,
        "alpha": alpha,
        "train_seeds": d.TRAIN_SEEDS,
        "calibration_seeds": d.CAL_SEEDS,
        "n_train": len(x_train),
        "n_calibration": len(x_cal),
    }
    return model, deviations, np.array(limits)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--alpha", type=float, default=DEFAULT_ALPHA)
    args = parser.parse_args()

    train_events = d.normal_events(d.TRAIN_SEEDS)
    cal_events = d.normal_events(d.CAL_SEEDS)
    model, deviations, limits = fit(train_events, cal_events, args.alpha)

    with open(MODEL_PATH, "w") as f:
        json.dump(model, f, indent=2)

    n = len(cal_events)
    budget = args.alpha / len(d.METRICS)
    print(f"alpha = {args.alpha}  (per-metric budget {budget:.6f} = {budget * n:.1f} of {n} calibration events)")
    print(f"train events = {model['n_train']}, calibration events = {n}\n")
    print(f"{'metric':18s}{'center':>9s}{'limit':>9s}{'cal events >= limit':>22s}")
    for i, m in enumerate(d.METRICS):
        over = int((deviations[:, i] >= limits[i]).sum())
        print(f"{m:18s}{model['centers'][m]:9.2f}{model['limits'][m]:9.2f}{over:22d}")
    flagged = int(((deviations / limits).max(axis=1) >= 1.0).sum())
    print(f"\ncalibration events with score >= 1.0: {flagged} of {n} ({flagged / n:.4%})")
    print(f"saved -> {MODEL_PATH.name}")


if __name__ == "__main__":
    main()