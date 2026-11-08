"""Sessions and notes."""
import os
import re

from . import status, util

MAX_NAME = 80
MAX_NOTE = 4000
MAX_BACKDATE = 7 * 86400


class SessionError(Exception):
    pass


def clean_name(name):
    name = re.sub(r"\s+", " ", util.safe_text(name or "", MAX_NAME * 2)).strip()
    name = re.sub(r"[^\w .,:@()+-]", "_", name)[:MAX_NAME]
    return name or "session"


def current(con):
    r = con.execute("SELECT * FROM sessions WHERE ended IS NULL ORDER BY started DESC LIMIT 1").fetchone()
    return dict(r) if r else None


def start(con, name, at=None, tags=""):
    if current(con):
        raise SessionError("A session is already open. End it first.")
    now = util.now_ts()
    started = util.parse_time(at) if at else now
    if started > now + 5:
        raise SessionError("A session can't start in the future.")
    if now - started > MAX_BACKDATE:
        raise SessionError("A session can be backdated by 7 days at most.")
    cur = con.execute("INSERT INTO sessions(name, started, host, egress, tags, created) VALUES(?,?,?,?,?,?)",
                      (clean_name(name), started, os.uname().nodename, status.egress()["label"],
                       clean_name(tags) if tags else "", now))
    con.commit()
    return cur.lastrowid


def end(con, sid):
    s = get(con, sid)
    if s["ended"]:
        raise SessionError("This session is already closed.")
    con.execute("UPDATE sessions SET ended=?, egress_end=? WHERE id=?", (util.now_ts(), status.egress()["label"], sid))
    con.commit()


def get(con, sid):
    r = con.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not r:
        raise SessionError(f"No session {sid}.")
    return dict(r)


def listing(con):
    out = []
    for r in con.execute("SELECT s.*, (SELECT COUNT(*) FROM notes n WHERE n.session_id=s.id) AS notes, "
                         "(SELECT COUNT(*) FROM events e WHERE e.session_id=s.id) AS events, "
                         "(SELECT COUNT(*) FROM net x WHERE x.session_id=s.id) AS packets "
                         "FROM sessions s ORDER BY started DESC"):
        d = dict(r)
        d["started_iso"], d["ended_iso"] = util.iso(d["started"]), util.iso(d["ended"])
        d["duration"] = (d["ended"] or util.now_ts()) - d["started"]
        out.append(d)
    return out


def add_note(con, sid, text, ts=None):
    get(con, sid)
    text = (text or "").strip()
    if not text:
        raise SessionError("Empty note.")
    if len(text) > MAX_NOTE:
        raise SessionError(f"Notes are limited to {MAX_NOTE} characters.")
    cur = con.execute("INSERT INTO notes(session_id, ts, text) VALUES(?,?,?)", (sid, ts or util.now_ts(), text))
    con.commit()
    return cur.lastrowid


def notes(con, sid):
    return [dict(r, iso=util.iso(r["ts"])) for r in
            con.execute("SELECT * FROM notes WHERE session_id=? ORDER BY ts", (sid,))]


def delete_note(con, sid, nid):
    con.execute("DELETE FROM notes WHERE id=? AND session_id=?", (nid, sid))
    con.commit()


def purge(con):
    """Delete every session with its evidence and notes, the command log and capture records. Not while one is open."""
    cur = current(con)
    if cur:
        raise SessionError(f"Session \"{cur['name']}\" is open: end it first.")
    n = con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    con.execute("DELETE FROM sessions")
    con.execute("DELETE FROM command_log")
    con.execute("DELETE FROM lab_events")
    con.commit()
    con.execute("VACUUM")
    return n


def delete(con, sid):
    get(con, sid)
    con.execute("DELETE FROM sessions WHERE id=?", (sid,))
    con.commit()
