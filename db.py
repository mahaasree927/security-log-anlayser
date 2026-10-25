"""SQLite storage for events and alerts."""
import sqlite3
from . import mitre

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    source      TEXT,
    source_file TEXT,
    line_no     INTEGER,
    host        TEXT,
    event_type  TEXT NOT NULL,
    username    TEXT,
    src_ip      TEXT,
    dst_ip      TEXT,
    dst_port    INTEGER,
    raw         TEXT NOT NULL,
    UNIQUE (source_file, line_no)          -- re-ingesting a file never duplicates rows
);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events (event_type, ts);
CREATE INDEX IF NOT EXISTS idx_events_ip      ON events (src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    rule           TEXT NOT NULL,
    severity       TEXT NOT NULL,
    src_ip         TEXT,
    username       TEXT,
    first_seen     TEXT,
    last_seen      TEXT,
    event_count    INTEGER,
    technique_id   TEXT,
    technique_name TEXT,
    tactic         TEXT,
    description    TEXT
);
"""


def connect(path: str = "sla.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def insert_events(conn, events) -> int:
    cur = conn.executemany(
        "INSERT OR IGNORE INTO events (ts, source, source_file, line_no, host, event_type,"
        " username, src_ip, dst_ip, dst_port, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [e.as_row() for e in events])
    conn.commit()
    return cur.rowcount


def clear_alerts(conn):
    conn.execute("DELETE FROM alerts")
    conn.commit()


def insert_alerts(conn, alerts):
    rows = []
    for a in alerts:
        name, tactic = mitre.describe(a.technique_id)
        rows.append((a.rule, a.severity, a.src_ip, a.username, a.first_seen.isoformat(),
                     a.last_seen.isoformat(), a.event_count, a.technique_id, name, tactic,
                     a.description))
    conn.executemany(
        "INSERT INTO alerts (rule, severity, src_ip, username, first_seen, last_seen,"
        " event_count, technique_id, technique_name, tactic, description)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
