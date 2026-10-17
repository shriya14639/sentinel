"""Post concurrent events from multiple simulated systems to the API."""

import asyncio
import os

import httpx
from data.simulation.generator import MetricGenerator


API_URL = os.environ.get("SENTINEL_API_URL", "http://127.0.0.1:8000")
SYSTEMS = int(os.environ.get("SIMULATED_SYSTEMS", "2"))
INTERVAL = float(os.environ.get("SIMULATION_INTERVAL_SECONDS", "1"))


async def main() -> None:
    if SYSTEMS < 2:
        raise ValueError("SIMULATED_SYSTEMS must be at least 2")
    if INTERVAL <= 0:
        raise ValueError("SIMULATION_INTERVAL_SECONDS must be greater than zero")

    generator = MetricGenerator(n_systems=SYSTEMS, seed=7, realtime=True)
    async with httpx.AsyncClient(timeout=15) as client:
        tick = 0
        while True:
            if tick and tick % 30 == 0:
                target = generator.system_ids[(tick // 30 - 1) % SYSTEMS]
                if generator.systems[target].anomaly is None:
                    generator.inject_anomaly(target, "resource_exhaustion", duration=5)

            events = generator.tick()
            for event in events:
                event.pop("injected_anomaly", None)
                event.pop("anomaly_type", None)
            responses = await asyncio.gather(
                *(
                    client.post(f"{API_URL.rstrip('/')}/events", json=event)
                    for event in events
                )
            )
            for response in responses:
                response.raise_for_status()

            tick += 1
            print(
                f"Submitted {len(events)} events from {SYSTEMS} systems "
                f"(tick {tick})",
                flush=True,
            )
            await asyncio.sleep(INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
