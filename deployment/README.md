# Sentinel API: local and LinuxONE deployment

The API receives raw events from the Part 1 stream at `POST /events`. It calls
Part 2 `score_event`, then Part 3 `classify_event`, calls Part 4
`explain_incident` only when the event is anomalous, and stores the final event
in SQLite. The explanation is advisory only. The detector does not use the
simulator's ground-truth labels.

## Run locally with Docker Compose

Run these commands in PowerShell from the repository root:

```powershell
docker compose -f deployment\docker-compose.yml up --build -d
docker compose -f deployment\docker-compose.yml ps
```

The API is at `http://localhost:8000`; interactive API docs are at
`http://localhost:8000/docs`. Compose also starts a simulator that concurrently
posts events from at least two simulated systems.

For local integration, CORS allows all origins, methods, and headers; credentialed
requests are disabled. Before exposing the API publicly, replace the wildcard
origin with an allowlist containing only the trusted frontend origin(s).

Check that the simulator is posting events:

```powershell
docker compose -f deployment\docker-compose.yml logs -f simulator
```

Open another PowerShell window and query the API:

```powershell
Invoke-RestMethod http://localhost:8000/health
Invoke-RestMethod "http://localhost:8000/incidents?limit=5"
Invoke-RestMethod "http://localhost:8000/incidents?severity=HIGH&system_id=server-1"
Invoke-RestMethod "http://localhost:8000/metrics/server-1?limit=20"
```

To submit one event manually, open `/docs`, expand `POST /events`, select
**Try it out**, and submit this JSON:

```json
{
  "event_id": "manual-001",
  "timestamp": "2026-10-10T12:00:00Z",
  "system_id": "server-1",
  "metrics": {
    "cpu_pct": 98,
    "memory_pct": 55,
    "network_in_mbps": 100,
    "network_out_mbps": 70,
    "failed_logins": 1,
    "error_rate": 1
  }
}
```

The response includes `anomaly_score`, `is_anomaly`, `severity`, deviated
metrics, `explanation`, and `record_id`. `GET /incidents` lists anomalous
events only; `GET /metrics/{system_id}` returns raw metric samples in
chronological order. Both endpoints return an `items` array. Non-anomalous
events are still stored and appear in the metric history.

SQLite data is stored under `../sentinel-data` relative to the Compose file by
default. It survives container restarts and rebuilds. Stop the containers with:

```powershell
docker compose -f deployment\docker-compose.yml down
```

Do not remove the `sentinel-data` folder if you want to preserve the database.

## Deploy on LinuxONE Community Cloud

1. Connect to your LinuxONE VM over SSH and install Docker Engine and the Docker
   Compose plugin using the official instructions for the VM's Linux
   distribution.
2. Clone the project on the VM, or transfer the project directory to it. Run
   all following commands from the repository root.
3. Choose a persistent data directory. For encryption at rest, it must reside
   on a filesystem that is encrypted by the cloud platform or by an
   administrator-managed encrypted block device. Do not assume Docker volumes
   or SQLite encrypt data automatically. Ask the VM administrator which
   encrypted mount is available; do not format or encrypt a disk that might
   contain existing data.
4. Set the compose bind-mount path to that encrypted mount, and grant the
   container's non-root UID (10001) access:

   ```sh
   sudo mkdir -p /mnt/sentinel-encrypted
   sudo chown 10001:10001 /mnt/sentinel-encrypted
   sudo chmod 700 /mnt/sentinel-encrypted
   export SENTINEL_DATA_DIR=/mnt/sentinel-encrypted
   export API_PORT=8000
   export SIMULATED_SYSTEMS=2
   ```

   Set `SENTINEL_DATA_DIR` to the administrator-provided encrypted mount path,
   not necessarily the example path above. Confirm the mounted filesystem's
   encryption status with the VM/cloud administrator before claiming
   encryption is enabled.
5. Start and inspect the services:

   ```sh
   docker compose -f deployment/docker-compose.yml up --build -d
   docker compose -f deployment/docker-compose.yml ps
   docker compose -f deployment/docker-compose.yml logs --tail=30 simulator
   curl http://127.0.0.1:8000/health
   curl "http://127.0.0.1:8000/incidents?limit=5"
   curl "http://127.0.0.1:8000/metrics/server-1?limit=20"
   ```

   The simulator submits each tick's events concurrently for at least two
   systems. To change the count, set `SIMULATED_SYSTEMS` to 2 or higher before
   starting Compose.
6. For a remote demo, allow inbound TCP port 8000 in the VM security group or
   firewall and use `http://<VM-public-address>:8000/docs`. Do not expose the
   API publicly without adding suitable authentication and network controls.

## Evidence for the technical design demo

Capture screenshots from the VM showing:

* `docker compose ... ps` with the API healthy and simulator running.
* `docker stats --no-stream` while the simulator is active, showing CPU and
  memory use under concurrent event traffic.
* The encrypted data mount configuration, including the administrator/cloud
  evidence that the mounted filesystem or backing volume is encrypted. A
  directory name or Docker volume alone is not proof of encryption.
* `/docs` or `curl` output showing a processed incident and persisted records.

Keep LLM credentials out of source control. Without credentials, Part 4 returns
its rule-based fallback explanation.
