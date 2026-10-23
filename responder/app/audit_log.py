"""Durable SQLite audit logging and duplicate-alert claims."""

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "audit.db"


def get_db_path() -> Path:
    return Path(os.environ.get("K8S_SENTINEL_AUDIT_DB", DEFAULT_DB_PATH))


def initialize_audit_db() -> None:
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path, timeout=5) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                technique_id TEXT,
                severity TEXT NOT NULL,
                action_taken TEXT NOT NULL,
                target TEXT,
                outcome TEXT NOT NULL,
                alert_key TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS processed_alerts (
                alert_key TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL
            )
            """
        )
        # Migrate databases created by the earlier Day 24 version.
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(audit_log)")
        }
        if "alert_key" not in columns:
            connection.execute("ALTER TABLE audit_log ADD COLUMN alert_key TEXT")
        connection.commit()


def claim_alert(alert_key: str) -> bool:
    """Atomically claim an alert key; return False if already processed/claimed."""
    initialize_audit_db()
    with sqlite3.connect(get_db_path(), timeout=5) as connection:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO processed_alerts (alert_key, first_seen)
            VALUES (?, ?)
            """,
            (alert_key, datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()
        return cursor.rowcount == 1


def log_action(
    *,
    technique_id: str | None,
    severity: str,
    action_taken: str,
    target: str | None,
    outcome: str,
    alert_key: str | None = None,
) -> None:
    """Persist an action outcome before returning to the caller."""
    initialize_audit_db()
    timestamp = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(get_db_path(), timeout=5) as connection:
        connection.execute(
            """
            INSERT INTO audit_log (
                timestamp, technique_id, severity, action_taken,
                target, outcome, alert_key
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                technique_id,
                severity,
                action_taken,
                target,
                outcome,
                alert_key,
            ),
        )
        connection.commit()
