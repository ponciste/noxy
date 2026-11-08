"""SQLite storage. The database is a rebuildable cache of parsed evidence plus your sessions and notes."""
import json
import sqlite3
import threading

from . import util

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    started REAL NOT NULL,
    ended REAL,
    host TEXT,
    egress TEXT,
    egress_end TEXT,
    tags TEXT DEFAULT '',
    verdict TEXT,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts REAL NOT NULL,
    text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts REAL NOT NULL,
    serial INTEGER NOT NULL,
    key TEXT, syscall TEXT, success TEXT, exit TEXT,
    pid INTEGER, ppid INTEGER, uid TEXT, auid TEXT,
    exe TEXT, comm TEXT, cmdline TEXT, cwd TEXT,
    dest TEXT, paths TEXT,
    UNIQUE(session_id, ts, serial)
);
CREATE INDEX IF NOT EXISTS ix_events_s ON events(session_id, ts);
CREATE TABLE IF NOT EXISTS audit_marks (
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts REAL NOT NULL, kind TEXT NOT NULL, detail TEXT,
    UNIQUE(session_id, ts, kind)
);
CREATE TABLE IF NOT EXISTS net (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,            -- dns | http | tls | syn | udp
    ts REAL NOT NULL,
    src TEXT, dst TEXT, sport INTEGER, dport INTEGER,
    name TEXT,                     -- dns qname, http host, tls sni
    method TEXT, uri TEXT, ua TEXT, qtype TEXT,
    count INTEGER DEFAULT 1,
    last_ts REAL,
    src_file TEXT
);
CREATE INDEX IF NOT EXISTS ix_net_s ON net(session_id, kind, ts);
-- inetsim: kept so databases from 0.1.x-0.2.0 open unchanged; no longer written (INetSim removed in 0.2.1)
CREATE TABLE IF NOT EXISTS inetsim (
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts REAL NOT NULL, line TEXT NOT NULL,
    UNIQUE(session_id, ts, line)
);
CREATE TABLE IF NOT EXISTS files (             -- Sysmon for Linux file creation (Event ID 11), added in 0.3.0
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts REAL NOT NULL, pid INTEGER, image TEXT, path TEXT NOT NULL, user TEXT,
    UNIQUE(session_id, ts, pid, path)
);
CREATE INDEX IF NOT EXISTS ix_files_s ON files(session_id, ts);
CREATE TABLE IF NOT EXISTS ingest (
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    last_run REAL, info TEXT,
    PRIMARY KEY(session_id, source)
);
CREATE TABLE IF NOT EXISTS command_log (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL, source TEXT, action TEXT, command TEXT NOT NULL,
    exit INTEGER, output TEXT, seconds REAL, python INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS lab_events (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL, detail TEXT
);
CREATE INDEX IF NOT EXISTS ix_lab_events ON lab_events(kind, ts);
CREATE TABLE IF NOT EXISTS self_pids (
    pid INTEGER NOT NULL, started REAL NOT NULL, last_seen REAL NOT NULL, role TEXT,
    PRIMARY KEY(pid, started)
);
"""

_lock = threading.Lock()


def path():
    return util.DATA / "noxy.db"


def connect():
    util.DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    con = sqlite3.connect(path(), timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA busy_timeout = 30000")
    return con


def init():
    with _lock:
        con = connect()
        try:
            con.executescript(SCHEMA)
            con.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema', ?)", (str(SCHEMA_VERSION),))
            con.commit()
        finally:
            con.close()
    try:
        path().chmod(0o600)
    except OSError:
        pass


def rows(cur):
    return [dict(r) for r in cur.fetchall()]


def get_meta(con, key, default=None):
    r = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return json.loads(r["value"]) if r and r["value"] and r["value"][:1] in "[{\"" else (r["value"] if r else default)


def set_meta(con, key, value):
    con.execute("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value if isinstance(value, str) else json.dumps(value)))
