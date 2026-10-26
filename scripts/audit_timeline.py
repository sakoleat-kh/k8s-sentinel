#!/usr/bin/env python3
"""Display the k8s-sentinel audit log as a chronological CLI timeline."""

import argparse
import sqlite3
from pathlib import Path
from textwrap import shorten

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = PROJECT_ROOT / "responder" / "data" / "audit.db"

COLUMNS = [
    ("timestamp", "TIMESTAMP"),
    ("technique_id", "TECHNIQUE"),
    ("severity", "SEVERITY"),
    ("action_taken", "ACTION"),
    ("outcome", "OUTCOME"),
]


def display(value, width):
    value = str(value) if value not in (None, "") else "—"
    return shorten(value, width=width, placeholder="…")

def main():
    parser = argparse.ArgumentParser(
        description="Print a chronological k8s-sentinel audit timeline."
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB,
                        help=f"SQLite database path (default: {DEFAULT_DB})")
    parser.add_argument("--limit", type=int, default=50,
                        help="Maximum records to display (default: 50; 0 = all)")
    parser.add_argument("--oldest-first", action="store_true",
                        help="Display the oldest records first")
    args = parser.parse_args()

    if args.limit < 0:
        parser.error("--limit must be 0 or greater")

    if not args.db.is_file():
        parser.error(f"Database not found: {args.db}")

    order = "ASC" if args.oldest_first else "DESC"
    query = (
        "SELECT timestamp, technique_id, severity, action_taken, outcome "
        "FROM audit_log "
        f"ORDER BY timestamp {order}, id {order}"
    )
    params = ()

    if args.limit:
        query += " LIMIT ?"
        params = (args.limit,)

    try:
        with sqlite3.connect(f"file:{args.db.resolve()}?mode=ro", uri=True) as conn:
            rows = conn.execute(query, params).fetchall()
    except sqlite3.Error as exc:
        parser.error(f"Could not read audit log: {exc}")

    widths = [34, 20, 10, 18, 20]
    headers = [label for _, label in COLUMNS]

    def format_row(values):
        return " | ".join(
            display(value, width).ljust(width)
            for value, width in zip(values, widths)
        )

    print(f"Audit timeline — {args.db}")
    print(f"Records displayed: {len(rows)}")
    print(format_row(headers))
    print("-+-".join("-" * width for width in widths))

    for row in rows:
        print(format_row(row))

    if not rows:
        print("No audit records found.")


if __name__ == "__main__":
    main()
