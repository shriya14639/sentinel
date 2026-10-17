"""
Sentinel synthetic metric generator (Person 1).

Produces events in the common schema:
{
  "event_id": "evt_000001",
  "timestamp": "2026-10-07T10:15:03Z",
  "system_id": "server-1",
  "metrics": {cpu_pct, memory_pct, network_in_mbps, network_out_mbps,
              failed_logins, error_rate},
  "injected_anomaly": false,          # ground-truth label (for validation only)
  "anomaly_type": null                # ground-truth type (for validation only)
}

Usage:
  python generator.py --sample            # writes ../sample_events.json
  python generator.py --sample --plot     # also saves sample_plot.png
"""
import argparse
import json
import math
import os
from datetime import datetime, timedelta, timezone

import numpy as np

ANOMALY_TYPES = ["cpu_spike", "memory_leak", "brute_force", "resource_exhaustion"]
METRICS = ["cpu_pct", "memory_pct", "network_in_mbps", "network_out_mbps",
           "failed_logins", "error_rate"]


class _System:
    """Holds one simulated server's baseline and anomaly state."""

    def __init__(self, system_id, rng):
        self.id = system_id
        self.rng = rng
        # Each server gets slightly different "normal"
        self.cpu_base = rng.uniform(25, 40)
        self.mem_base = rng.uniform(50, 62)
        self.net_in_base = rng.uniform(80, 130)
        self.net_out_base = rng.uniform(50, 90)
        self.err_base = rng.uniform(0.6, 1.4)
        self.phase = rng.uniform(0, 2 * math.pi)
        self.mem_drift = 0.0
        self.t = 0
        self.anomaly = None  # dict: type, total, step

    def start_anomaly(self, a_type, duration):
        if a_type not in ANOMALY_TYPES:
            raise ValueError(f"Unknown anomaly type '{a_type}'. Choose from {ANOMALY_TYPES}")
        self.anomaly = {"type": a_type, "total": duration, "step": 0}

    def next_metrics(self):
        r = self.rng
        self.t += 1
        daily = math.sin(self.t / 20.0 + self.phase)  # slow "daily" cycle

        # slow random-walk drift in memory, gently pulled back to 0
        self.mem_drift = 0.97 * self.mem_drift + r.normal(0, 0.3)

        cpu = self.cpu_base + 5 * daily + r.normal(0, 4)
        mem = self.mem_base + 2 * daily + self.mem_drift + r.normal(0, 1)
        net_in = self.net_in_base + 15 * daily + r.normal(0, 10)
        net_out = self.net_out_base + 10 * daily + r.normal(0, 8)
        logins = float(r.poisson(0.7))
        err = self.err_base + 0.2 * daily + r.normal(0, 0.25)

        label, a_type = False, None
        if self.anomaly:
            a = self.anomaly
            a["step"] += 1
            frac = a["step"] / a["total"]  # 0 -> 1 through the anomaly
            label, a_type = True, a["type"]

            if a_type == "cpu_spike":  # single-metric spike
                cpu = r.uniform(88, 99)
            elif a_type == "memory_leak":  # gradual ramp
                mem = mem + 38 * frac + r.normal(0, 1)
            elif a_type == "brute_force":  # multivariate: logins + mild cpu/net/err
                logins = float(r.integers(25, 60))
                cpu += r.uniform(12, 22)
                net_in += r.uniform(30, 60)
                err += r.uniform(1.0, 2.0)
            elif a_type == "resource_exhaustion":  # multivariate: all load metrics up
                cpu = r.uniform(80, 95)
                mem += r.uniform(18, 28)
                net_in += r.uniform(120, 220)
                net_out += r.uniform(80, 140)
                err += r.uniform(4, 9)
                logins = float(r.poisson(3))

            if a["step"] >= a["total"]:
                self.anomaly = None

        metrics = {
            "cpu_pct": round(float(np.clip(cpu, 0, 100)), 2),
            "memory_pct": round(float(np.clip(mem, 0, 100)), 2),
            "network_in_mbps": round(float(max(net_in, 0)), 2),
            "network_out_mbps": round(float(max(net_out, 0)), 2),
            "failed_logins": int(logins),
            "error_rate": round(float(np.clip(err, 0, 100)), 2),
        }
        return metrics, label, a_type


class MetricGenerator:
    def __init__(self, n_systems=5, seed=42, realtime=False, step_seconds=10):
        """
        realtime=True  -> timestamps are the current UTC time (use for live replay)
        realtime=False -> simulated clock advancing step_seconds per tick (use for files)
        """
        self.rng = np.random.default_rng(seed)
        self.systems = {f"server-{i}": _System(f"server-{i}", self.rng)
                        for i in range(1, n_systems + 1)}
        self.realtime = realtime
        self.step = timedelta(seconds=step_seconds)
        self.clock = datetime(2026, 10, 7, 9, 0, 0, tzinfo=timezone.utc)
        self.counter = 0

    @property
    def system_ids(self):
        return list(self.systems)

    def inject_anomaly(self, system_id, a_type, duration=10):
        if system_id not in self.systems:
            raise ValueError(f"Unknown system '{system_id}'. Have: {self.system_ids}")
        self.systems[system_id].start_anomaly(a_type, duration)

    def _ts(self):
        t = datetime.now(timezone.utc) if self.realtime else self.clock
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    def generate_event(self, system_id):
        metrics, label, a_type = self.systems[system_id].next_metrics()
        self.counter += 1
        return {
            "event_id": f"evt_{self.counter:06d}",
            "timestamp": self._ts(),
            "system_id": system_id,
            "metrics": metrics,
            "injected_anomaly": label,
            "anomaly_type": a_type,
        }

    def tick(self):
        """One event for every system (one 'time step')."""
        events = [self.generate_event(sid) for sid in self.systems]
        if not self.realtime:
            self.clock += self.step
        return events


def build_sample(n_ticks=30, n_systems=3, seed=42):
    """Deterministic sample: 90 events, 4 injected anomalies of different types."""
    gen = MetricGenerator(n_systems=n_systems, seed=seed)
    schedule = {  # tick -> (system, type, duration)
        8: ("server-2", "brute_force", 6),
        12: ("server-1", "cpu_spike", 4),
        18: ("server-3", "resource_exhaustion", 5),
        22: ("server-1", "memory_leak", 7),
    }
    events = []
    for tick in range(n_ticks):
        if tick in schedule:
            gen.inject_anomaly(*schedule[tick])
        events.extend(gen.tick())
    return events


def plot_events(events, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    systems = sorted({e["system_id"] for e in events})
    fig, axes = plt.subplots(len(METRICS), 1, figsize=(12, 2.2 * len(METRICS)), sharex=True)
    for ax, m in zip(axes, METRICS):
        for sid in systems:
            ev = [e for e in events if e["system_id"] == sid]
            ys = [e["metrics"][m] for e in ev]
            line, = ax.plot(range(len(ev)), ys, label=sid, lw=1)
            bad = [i for i, e in enumerate(ev) if e["injected_anomaly"]]
            ax.scatter(bad, [ys[i] for i in bad], color=line.get_color(),
                       edgecolor="red", zorder=3, s=30)
        ax.set_ylabel(m, fontsize=8)
    axes[0].legend(ncol=len(systems), fontsize=8)
    axes[-1].set_xlabel("tick (red-edged dots = injected anomalies)")
    plt.tight_layout()
    plt.savefig(path, dpi=110)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--sample", action="store_true", help="write ../sample_events.json")
    p.add_argument("--plot", action="store_true", help="save sample_plot.png")
    args = p.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    if args.sample:
        events = build_sample()
        out = os.path.join(here, "..", "sample_events.json")
        with open(out, "w") as f:
            json.dump(events, f, indent=2)
        n_bad = sum(e["injected_anomaly"] for e in events)
        print(f"Wrote {len(events)} events ({n_bad} anomalous) -> {os.path.normpath(out)}")
        if args.plot:
            plot_events(events, os.path.join(here, "sample_plot.png"))
            print("Saved sample_plot.png")
    else:
        p.print_help()
