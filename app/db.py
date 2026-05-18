import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


DB_PATH = Path(os.getenv("ASTRA_DB_PATH", "astra.db"))


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_db():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True) if DB_PATH.parent != Path(".") else None
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS sites (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                domain TEXT NOT NULL DEFAULT '',
                server_type TEXT NOT NULL DEFAULT 'auto',
                os_type TEXT NOT NULL DEFAULT 'linux',
                mode TEXT NOT NULL DEFAULT 'autoprotect',
                enrollment_token TEXT NOT NULL UNIQUE,
                agent_token TEXT,
                dashboard_token TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_heartbeat_at TEXT
            );

            CREATE TABLE IF NOT EXISTS agents (
                site_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                version TEXT NOT NULL DEFAULT '',
                enrolled_at TEXT NOT NULL,
                last_heartbeat_at TEXT,
                FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                site_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                user_agent TEXT,
                rule_id TEXT,
                event_count INTEGER NOT NULL DEFAULT 1,
                sample_lines TEXT NOT NULL DEFAULT '[]',
                explanation TEXT NOT NULL,
                solutions TEXT NOT NULL DEFAULT '[]',
                action_taken TEXT NOT NULL DEFAULT 'Monitored',
                should_block INTEGER NOT NULL DEFAULT 0,
                block_duration_hours INTEGER NOT NULL DEFAULT 24,
                created_at TEXT NOT NULL,
                FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS blocks (
                id TEXT PRIMARY KEY,
                site_id TEXT NOT NULL,
                event_id TEXT,
                source_ip TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                expires_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE
            );
            """
        )


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def json_dumps(value):
    return json.dumps(value or [], separators=(",", ":"))


def json_loads(value):
    if not value:
        return []
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return []
