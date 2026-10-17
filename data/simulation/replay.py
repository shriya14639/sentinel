"""
Sentinel streaming replay (Person 1).

Pushes one event per system every --interval seconds, like a real monitoring agent.

Examples:
  python replay.py --systems 5 --interval 1                 # print events only
  python replay.py --url http://localhost:8000/events       # POST to Person 5's API
  python replay.py --out events.jsonl --count 60            # write 60 ticks to a file

Live injection (type in the terminal while it runs):
  inject server-2 brute_force        (optional 3rd arg = duration, default 10)
  types                              (list anomaly types)
  quit
"""
import argparse
import json
import sys
import threading
import time
import urllib.error
import urllib.request

from generator import ANOMALY_TYPES, MetricGenerator


def post_event(url, event):
    req = urllib.request.Request(
        url, data=json.dumps(event).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status


def command_loop(gen, stop):
    for line in sys.stdin:
        parts = line.strip().split()
        if not parts:
            continue
        cmd = parts[0].lower()
        try:
            if cmd == "inject" and len(parts) >= 3:
                dur = int(parts[3]) if len(parts) > 3 else 10
                gen.inject_anomaly(parts[1], parts[2], dur)
                print(f">>> Injected {parts[2]} on {parts[1]} for {dur} ticks", flush=True)
            elif cmd == "types":
                print("Anomaly types:", ", ".join(ANOMALY_TYPES), flush=True)
            elif cmd in ("quit", "exit"):
                stop.set()
                return
            else:
                print("Usage: inject <system_id> <type> [duration] | types | quit", flush=True)
        except ValueError as e:
            print("Error:", e, flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--systems", type=int, default=5)
    p.add_argument("--interval", type=float, default=1.0, help="seconds between ticks")
    p.add_argument("--url", default=None, help="POST each event here (e.g. http://localhost:8000/events)")
    p.add_argument("--out", default=None, help="append events as JSON lines to this file")
    p.add_argument("--count", type=int, default=0, help="stop after N ticks (0 = run forever)")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    gen = MetricGenerator(n_systems=args.systems, seed=args.seed, realtime=True)
    stop = threading.Event()
    threading.Thread(target=command_loop, args=(gen, stop), daemon=True).start()

    out_f = open(args.out, "a") if args.out else None
    print(f"Streaming {args.systems} systems every {args.interval}s. "
          f"Type 'inject server-1 cpu_spike' to inject. Ctrl+C to stop.", flush=True)
    ticks = 0
    try:
        while not stop.is_set():
            start = time.time()
            for ev in gen.tick():
                if args.url:
                    try:
                        post_event(args.url, ev)
                    except (urllib.error.URLError, OSError) as e:
                        print(f"[warn] POST failed: {e}", flush=True)
                if out_f:
                    out_f.write(json.dumps(ev) + "\n")
                    out_f.flush()
                if not args.quiet:
                    flag = "ANOMALY" if ev["injected_anomaly"] else "ok"
                    m = ev["metrics"]
                    print(f"{ev['timestamp']} {ev['system_id']:<9} cpu={m['cpu_pct']:5.1f} "
                          f"mem={m['memory_pct']:5.1f} in={m['network_in_mbps']:6.1f} "
                          f"logins={m['failed_logins']:2d} err={m['error_rate']:4.1f}  [{flag}]",
                          flush=True)
            ticks += 1
            if args.count and ticks >= args.count:
                break
            time.sleep(max(0, args.interval - (time.time() - start)))
    except KeyboardInterrupt:
        pass
    finally:
        if out_f:
            out_f.close()
        print("Stopped.")


if __name__ == "__main__":
    main()
