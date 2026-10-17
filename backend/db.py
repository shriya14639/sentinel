"""SQLCipher persistence for processed Sentinel events."""

import json
import os
import re
from contextlib import contextmanager
from pathlib import Path

from sqlcipher3 import dbapi2 as sqlite3


def _database_path() -> Path:
    configured_path = os.environ.get("SENTINEL_DB_PATH")
    if configured_path:
        return Path(configured_path)
    return Path(__file__).resolve().parent / "sentinel-encrypted.db"


@contextmanager
def _connection():
    key = os.environ.get("SENTINEL_DB_KEY", "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", key):
        raise RuntimeError(
            "SENTINEL_DB_KEY is missing or invalid; refusing to open the database."
        )

    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)

    try:
        connection.execute(f"""PRAGMA key = "x'{key}'" """)
        connection.row_factory = sqlite3.Row
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()

        with connection:
            yield connection
    finally:
        connection.close()


def init_db() -> None:
    """Create the event table and indexes if they do not exist."""
    with _connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                system_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                is_anomaly INTEGER NOT NULL,
                metrics_json TEXT NOT NULL,
                processed_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_anomaly_system "
            "ON events(is_anomaly, system_id, id DESC)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_severity "
            "ON events(severity, id DESC)"
        )


def save_event(event: dict) -> dict:
    """Store a fully processed event and return it with its database record ID."""
    stored_event = dict(event)
    event_json = json.dumps(stored_event, allow_nan=False)
    metrics_json = json.dumps(stored_event["metrics"], allow_nan=False)
    event_id = stored_event.get("event_id")
    if not isinstance(event_id, str):
        event_id = None

    with _connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO events (
                event_id, system_id, timestamp, severity, is_anomaly,
                metrics_json, processed_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                stored_event["system_id"],
                stored_event["timestamp"],
                stored_event["severity"],
                int(stored_event["is_anomaly"]),
                metrics_json,
                event_json,
            ),
        )
        record_id = cursor.lastrowid
        stored_event["record_id"] = record_id
        connection.execute(
            "UPDATE events SET processed_json = ? WHERE id = ?",
            (json.dumps(stored_event, allow_nan=False), record_id),
        )
    return stored_event


def list_incidents(
    severity: str | None, system_id: str | None, limit: int, offset: int
) -> tuple[int, list[dict]]:
    """Return anomalous events with optional filters and pagination."""
    clauses = ["is_anomaly = 1"]
    parameters: list[object] = []
    if severity:
        clauses.append("severity = ?")
        parameters.append(severity.upper())
    if system_id:
        clauses.append("system_id = ?")
        parameters.append(system_id)
    where = " AND ".join(clauses)

    with _connection() as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM events WHERE {where}", parameters
        ).fetchone()[0]
        rows = connection.execute(
            f"""
            SELECT processed_json FROM events
            WHERE {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            [*parameters, limit, offset],
        ).fetchall()
    return total, [json.loads(row["processed_json"]) for row in rows]


def list_metric_history(system_id: str, limit: int) -> list[dict]:
    """Return recent raw metrics in chronological order for charting."""
    with _connection() as connection:
        rows = connection.execute(
            """
            SELECT event_id, timestamp, system_id, metrics_json
            FROM events
            WHERE system_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (system_id, limit),
        ).fetchall()
    return [
        {
            "event_id": row["event_id"],
            "timestamp": row["timestamp"],
            "system_id": row["system_id"],
            "metrics": json.loads(row["metrics_json"]),
        }
        for row in reversed(rows)
    ]
