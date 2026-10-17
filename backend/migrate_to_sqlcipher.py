"""Copy a plain SQLite Sentinel database into a new SQLCipher database."""

import os
import re
import sqlite3
from pathlib import Path

from dotenv import load_dotenv
from sqlcipher3 import dbapi2 as sqlcipher

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "sentinel-data" / "sentinel.db"
DESTINATION = ROOT / "sentinel-data" / "sentinel-encrypted.db"

load_dotenv(ROOT / ".env")


def main():
    key = os.environ.get("SENTINEL_DB_KEY", "")

    if not re.fullmatch(r"[0-9a-fA-F]{64}", key):
        raise SystemExit("STOP: Encryption key is missing or invalid.")

    if not SOURCE.is_file():
        raise SystemExit(f"STOP: Source database not found: {SOURCE}")

    if DESTINATION.exists():
        raise SystemExit(
            f"STOP: Destination already exists: {DESTINATION}. "
            "Nothing was overwritten."
        )

    source = sqlite3.connect(SOURCE)
    destination = None

    try:
        source.row_factory = sqlite3.Row
        rows = source.execute(
            """
            SELECT id, event_id, system_id, timestamp, severity,
                   is_anomaly, metrics_json, processed_json
            FROM events ORDER BY id
            """
        ).fetchall()

        if not rows:
            raise RuntimeError("Source database contains no event records.")

        print(f"Source records found: {len(rows)}")

        destination = sqlcipher.connect(str(DESTINATION))
        destination.execute(f"""PRAGMA key = "x'{key}'" """)

        cipher_version = destination.execute(
            "PRAGMA cipher_version"
        ).fetchone()

        if not cipher_version or not cipher_version[0]:
            raise RuntimeError("SQLCipher encryption is not available.")

        print("SQLCipher version:", cipher_version[0])

        destination.execute("PRAGMA journal_mode = DELETE")
        destination.execute(
            """
            CREATE TABLE events (
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
        destination.execute(
            "CREATE INDEX idx_events_anomaly_system "
            "ON events(is_anomaly, system_id, id DESC)"
        )
        destination.execute(
            "CREATE INDEX idx_events_severity "
            "ON events(severity, id DESC)"
        )

        destination.executemany(
            """
            INSERT INTO events (
                id, event_id, system_id, timestamp, severity,
                is_anomaly, metrics_json, processed_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [tuple(row) for row in rows],
        )
        destination.commit()

        copied_count = destination.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]
        source_ids = (rows[0]["id"], rows[-1]["id"])
        destination_ids = destination.execute(
            "SELECT MIN(id), MAX(id) FROM events"
        ).fetchone()

        integrity = destination.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        if (
            copied_count != len(rows)
            or tuple(destination_ids) != source_ids
            or integrity != "ok"
        ):
            raise RuntimeError(
                "Verification failed. Keep the original database unchanged."
            )

        print("Encrypted database created and verified.")
        print("Source record count:", len(rows))
        print("Encrypted record count:", copied_count)
        print("First and last record IDs:", source_ids)
        print("Integrity check:", integrity)
        print("Destination:", DESTINATION)

    finally:
        source.close()
        if destination is not None:
            destination.close()


if __name__ == "__main__":
    main()
