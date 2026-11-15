
import os
import sys
import sqlite3

from pathlib import Path
from datetime import datetime


# Project directory
BASE_DIR = Path(__file__).resolve().parent

# Use a persistent, user-specific location for packaged applications.
if getattr(sys, "frozen", False):
    LOCAL_APP_DATA = Path(
        os.environ.get(
            "LOCALAPPDATA",
            Path.home() / "AppData" / "Local"
        )
    )

    DATA_DIR = (
        LOCAL_APP_DATA
        / "AttackSurfaceAnalyzer"
        / "data"
    )

else:
    # Development mode: preserve existing database location
    DATA_DIR = BASE_DIR / "data"


DB_PATH = DATA_DIR / "analyzer.db"



def get_connection():
    """Open a connection to the SQLite database."""

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def init_db():
    """Create database tables if they do not exist."""

    connection = get_connection()

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                hostname TEXT,
                total_findings INTEGER NOT NULL DEFAULT 0
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                item TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                recommendation TEXT,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(scan_id)
                    ON DELETE CASCADE
            )
        """)

        connection.commit()

    finally:
        connection.close()


def save_scan(records, hostname=None):
    """Save one scan and all its findings."""

    scan_time = (
        records[0].get("scan_time")
        if records
        else datetime.now().astimezone().isoformat(
            timespec="seconds"
        )
    )

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO scans (
                scan_time, hostname, total_findings
            )
            VALUES (?, ?, ?)
        """, (scan_time, hostname, len(records)))

        scan_id = cursor.lastrowid

        finding_rows = [
            (
                scan_id,
                record.get("category", "Unknown"),
                record.get("item", "Unknown"),
                record.get("description", ""),
                record.get("severity", "Informational"),
                record.get("risk_score", 0) or 0,
                record.get("recommendation", "")
            )
            for record in records
        ]

        cursor.executemany("""
            INSERT INTO findings (
                scan_id, category, item, description,
                severity, risk_score, recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, finding_rows)

        connection.commit()
        return scan_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_scans(limit=20):
    """Return recent scans, newest first."""

    connection = get_connection()

    try:
        rows = connection.execute("""
            SELECT *
            FROM scans
            ORDER BY scan_id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_findings(scan_id):
    """Return findings for a particular scan."""

    connection = get_connection()

    try:
        rows = connection.execute("""
            SELECT *
            FROM findings
            WHERE scan_id = ?
            ORDER BY finding_id
        """, (scan_id,)).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")
    print(f"Database location: {DB_PATH}")
