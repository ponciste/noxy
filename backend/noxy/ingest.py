"""Refresh: reads the audit log and the capture ring for one session into SQLite."""
import datetime as dt
import json
import os
import re
from pathlib import Path

from . import analysis, audit, pcap, sysmon, util

PCAP_NAME = re.compile(r"(\d{8}T\d{6})Z?\.pcap$")


def _set_info(con, sid, source, info):
    con.execute("INSERT INTO ingest(session_id, source, last_run, info) VALUES(?,?,?,?) "
                "ON CONFLICT(session_id, source) DO UPDATE SET last_run=excluded.last_run, info=excluded.info",
                (sid, source, util.now_ts(), json.dumps(info)))


def _get_info(con, sid, source):
    r = con.execute("SELECT info FROM ingest WHERE session_id=? AND source=?", (sid, source)).fetchone()
    try:
        return json.loads(r["info"]) if r and r["info"] else {}
    except ValueError:
        return {}


def earliest_record(paths):
    for p in paths:                                  # oldest file first
        try:
            with open(p, errors="replace") as fh:
                for line in fh:
                    m = audit.LINE_RE.search(line)
                    if m:
                        return float(m.group(2))
        except OSError:
            continue
    return None


def ingest_audit(con, s, audit_dir=None):
    sid, since, until = s["id"], s["started"], s["ended"]
    files = audit.log_files(audit_dir)
    d = audit_dir or util.AUDIT_DIR
    if not files:
        try:
            Path(d).stat()
            list(Path(d).iterdir())
            err = f"No audit.log files in {d}: is auditd installed and running? (sudo python3 noxy.py setup lab)"
        except PermissionError:
            err = (f"Can't read {d}. Run `sudo python3 noxy.py setup lab`, then log out and back in so your "
                   "account picks up the noxy group.")
        except OSError:
            err = f"{d} does not exist: auditd is not installed (sudo python3 noxy.py setup lab)."
        _set_info(con, sid, "audit", {"error": err})
        return {"error": err}
    try:
        events, marks = audit.parse(files, since, until)
    except PermissionError as e:
        err = (f"Can't read {e.filename}. Run `sudo python3 noxy.py setup lab`, then log out and back in so your "
               "account picks up the noxy group.")
        _set_info(con, sid, "audit", {"error": err})
        return {"error": err}
    before = con.total_changes
    con.executemany(
        "INSERT OR IGNORE INTO events(session_id, ts, serial, key, syscall, success, exit, pid, ppid, uid, auid, exe, "
        "comm, cmdline, cwd, dest, paths) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(sid, e["ts"], e["serial"], e["key"], e.get("syscall"), e.get("success"), e.get("exit"), e.get("pid"),
          e.get("ppid"), e.get("uid"), e.get("auid"), e.get("exe"), e.get("comm"), e.get("cmdline"), e.get("cwd"),
          e.get("dest"), json.dumps(e.get("paths") or [])) for e in events])
    added = con.total_changes - before
    con.executemany("INSERT OR IGNORE INTO audit_marks(session_id, ts, kind, detail) VALUES(?,?,?,?)",
                    [(sid, m["ts"], m["kind"], m["detail"]) for m in marks])
    keys = {r[0] for r in con.execute("SELECT DISTINCT key FROM events WHERE session_id=?", (sid,))}
    earliest = earliest_record(files)
    info = {"files": [str(f) for f in files], "earliest": earliest, "parsed": len(events), "added": added,
            "rules": True if keys & {"exec", "net"} else (False if earliest is not None else None)}
    _set_info(con, sid, "audit", info)
    return info


def pcap_files(pcap_dir=None):
    d = Path(pcap_dir or util.PCAP_DIR)
    try:
        return sorted(p for p in d.glob("*.pcap") if p.is_file())
    except OSError:
        return []


def _file_start(p):
    m = PCAP_NAME.search(p.name)
    if m:
        try:
            return dt.datetime.strptime(m.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=util.UTC).timestamp()
        except ValueError:
            pass
    return None


def ingest_pcap(con, s, pcap_dir=None):
    sid, since, until = s["id"], s["started"], s["ended"]
    d = Path(pcap_dir or util.PCAP_DIR)
    prev = _get_info(con, sid, "pcap").get("files", {})
    info = {"dir": str(d), "files": {}, "errors": [], "packets": 0}
    try:
        files = pcap_files(d)
        if not files and not os.path.exists(d):
            info["error"] = f"{d} does not exist: the capture service is not set up (sudo python3 noxy.py setup lab)."
    except PermissionError:
        files = []
        info["error"] = f"Can't read {d}: log out and back in after `noxy setup lab` to pick up the noxy group."
    for p in files:
        try:
            st = p.stat()
        except OSError:
            continue
        start = _file_start(p) or st.st_mtime - 600
        if st.st_mtime < since or (until and start > until):
            continue
        sig = [st.st_size, st.st_mtime]
        if prev.get(p.name, {}).get("sig") == sig:
            info["files"][p.name] = prev[p.name]
            info["packets"] += prev[p.name].get("packets", 0)
            continue
        con.execute("DELETE FROM net WHERE session_id=? AND src_file=?", (sid, p.name))
        try:
            r = pcap.parse_file(p, since, until)
        except (pcap.PcapError, OSError) as e:
            info["errors"].append(f"{p.name}: {e}")
            continue
        rows = []
        for kind in ("dns", "http", "tls", "syn", "udp"):
            for x in r[kind]:
                rows.append((sid, kind, x["ts"], x.get("src"), x.get("dst"), x.get("sport"), x.get("dport"),
                             x.get("name"), x.get("method"), x.get("uri"), x.get("ua"), x.get("qtype"),
                             x.get("count", 1), x.get("last_ts"), p.name))
        con.executemany("INSERT INTO net(session_id, kind, ts, src, dst, sport, dport, name, method, uri, ua, qtype, "
                        "count, last_ts, src_file) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        info["files"][p.name] = {"sig": sig, "packets": r["packets"], "rows": len(rows)}
        info["packets"] += r["packets"]
    for name in set(prev) - set(info["files"]):
        if not os.path.exists(d / name):
            info["files"][name] = dict(prev[name], gone=True)          # rotated away; rows stay
    _set_info(con, sid, "pcap", info)
    return info


def ingest_files(con, s, log_path=None):
    """Sysmon file-creation events into the files table (INSERT OR IGNORE: refreshes are idempotent)."""
    sid, since, until = s["id"], s["started"], s["ended"]
    path = Path(log_path or sysmon.LOG)
    files = sysmon.log_files(path)
    if not files:
        if os.path.isdir(path.parent) and not os.access(path.parent, os.R_OK | os.X_OK):
            err = f"Can't read {path.parent}: reboot (or log out and in) after `sudo python3 noxy.py setup sysmon`."
        else:
            err = f"No Sysmon log at {path}: file creation is not watched (sudo python3 noxy.py setup sysmon)."
        info = {"error": err, "installed": False}
        _set_info(con, sid, "files", info)
        return info
    try:
        events, _, capped = sysmon.parse(files, since, until)
    except PermissionError as e:
        info = {"error": f"Can't read {e.filename}: reboot after `sudo python3 noxy.py setup sysmon`.", "installed": True}
        _set_info(con, sid, "files", info)
        return info
    before = con.total_changes
    con.executemany("INSERT OR IGNORE INTO files(session_id, ts, pid, image, path, user) VALUES(?,?,?,?,?,?)",
                    [(sid, e["ts"], e["pid"], e["image"], e["path"], e["user"]) for e in events])
    info = {"files": [str(f) for f in files], "earliest": sysmon.earliest_event(files), "parsed": len(events),
            "added": con.total_changes - before, "capped": capped, "installed": True}
    _set_info(con, sid, "files", info)
    return info


def refresh(con, sid, home=None, audit_dir=None, pcap_dir=None, sysmon_log=None):
    s = con.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not s:
        raise KeyError(sid)
    s = dict(s)
    out = {"audit": ingest_audit(con, s, audit_dir), "pcap": ingest_pcap(con, s, pcap_dir),
           "files": ingest_files(con, s, sysmon_log)}
    art = analysis.artefacts(home or Path.home(), s["started"], s["ended"])
    _set_info(con, sid, "artefacts", art)
    out["artefacts"] = {"findings": len(art["findings"]), "files": len(art["files"])}
    con.commit()
    x = analysis.execution(con, sid)
    con.execute("UPDATE sessions SET verdict=? WHERE id=?", (x["verdict"]["level"], sid))
    con.commit()
    out["verdict"] = x["verdict"]
    return out
