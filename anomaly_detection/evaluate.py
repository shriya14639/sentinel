"""Evaluate the detector on the held-out test streams (10 seeds, injected anomalies).

Run from the repo root:   python anomaly_detection/evaluate.py

The labels (injected_anomaly, anomaly_type) are read HERE, only to grade the answers.
score_event never uses them.
"""
import numpy as np

import sim_data as d
from score import score_event

SYSTEMS_IN_DEMO = 5            # replay.py default
EVENTS_PER_HOUR = 3600         # replay.py default: one event per system per second


def find_windows(stream):
    """Runs of consecutive anomalous events of one type in one system's stream.

    Returns a list of (anomaly_type, start_index, end_index_exclusive).
    """
    windows, start = [], None
    for i, e in enumerate(stream + [None]):        # the trailing None closes the last window
        kind = e["anomaly_type"] if e is not None else None
        if start is not None and kind != stream[start]["anomaly_type"]:
            windows.append((stream[start]["anomaly_type"], start, i))
            start = None
        if start is None and kind is not None:
            start = i
    return windows


def confusion(truth, pred):
    tp = int((pred & truth).sum())
    fp = int((pred & ~truth).sum())
    fn = int((~pred & truth).sum())
    tn = int((~pred & ~truth).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return tp, fp, fn, tn, precision, recall, f1


def main():
    truth_all, pred_all, score_all, type_all = [], [], [], []
    seed_f1, windows = [], []          # windows: (type, detected, delay_in_ticks)
    for seed in d.TEST_SEEDS:
        events = d.labeled_stream(seed)
        results = [score_event(e) for e in events]
        truth = np.array([e["injected_anomaly"] for e in events])
        pred = np.array([r["is_anomaly"] for r in results])
        truth_all.append(truth)
        pred_all.append(pred)
        score_all.append(np.array([r["anomaly_score"] for r in results]))
        type_all.append(np.array([e["anomaly_type"] or "normal" for e in events]))
        seed_f1.append(confusion(truth, pred)[6])
        for sid in sorted({e["system_id"] for e in events}):
            idx = [i for i, e in enumerate(events) if e["system_id"] == sid]
            stream = [events[i] for i in idx]
            flags = [results[i]["is_anomaly"] for i in idx]
            for kind, a, b in find_windows(stream):
                hits = [k for k in range(a, b) if flags[k]]
                windows.append((kind, bool(hits), hits[0] - a if hits else None))

    truth, pred = np.concatenate(truth_all), np.concatenate(pred_all)
    scores, types = np.concatenate(score_all), np.concatenate(type_all)

    tp, fp, fn, tn, precision, recall, f1 = confusion(truth, pred)
    fpr = fp / (fp + tn)
    print(f"test events: {len(truth)} | anomalous: {int(truth.sum())} ({truth.mean():.1%}) | windows: {len(windows)}\n")
    print("EVENT LEVEL")
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  precision={precision:.3f}  recall={recall:.3f}  F1={f1:.3f}  false-positive rate={fpr:.4f}")
    print(f"  F1 per test seed: mean={np.mean(seed_f1):.3f}  std={np.std(seed_f1):.3f}  min={np.min(seed_f1):.3f}")
    per_hour = fpr * SYSTEMS_IN_DEMO * EVENTS_PER_HOUR
    print(f"  false alarms per hour at {SYSTEMS_IN_DEMO} systems x 1 event/s: about {per_hour:.0f}")

    print("\nBY ANOMALY TYPE")
    print(f"  {'type':20s}{'events':>7s}{'event recall':>14s}{'windows':>9s}{'detected':>9s}{'median delay':>14s}{'max delay':>11s}")
    for kind in d.ANOMALY_TYPES:
        mask = types == kind
        rec = pred[mask].mean()
        rows = [w for w in windows if w[0] == kind]
        delays = [w[2] for w in rows if w[1]]
        print(f"  {kind:20s}{mask.sum():7d}{rec:14.2f}{len(rows):9d}{sum(w[1] for w in rows):9d}"
              f"{np.median(delays):14.1f}{max(delays):11d}")
    print(f"  window recall overall: {sum(w[1] for w in windows)}/{len(windows)}   (delay = ticks after the window starts)")

    print("\nANOMALY SCORE DISTRIBUTION (1.0 = edge of normal)")
    n = scores[types == "normal"]
    print(f"  normal events      : median={np.median(n):.2f}  p99={np.percentile(n, 99):.2f}  "
          f"p99.9={np.percentile(n, 99.9):.2f}  max={n.max():.2f}")
    for kind in d.ANOMALY_TYPES:
        s = scores[types == kind]
        print(f"  {kind:19s}: min={s.min():.2f}  median={np.median(s):.2f}  max={s.max():.2f}")


if __name__ == "__main__":
    main()