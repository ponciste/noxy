"""Lab controls, command log, disk status, public IP.

Everything here is a fixed action: no free-text commands, no sample-derived arguments. Every command noxy executes
(or every action it performs in Python that has a terminal equivalent) is written to the command log, so you can
see exactly what ran and repeat it yourself.
"""
import json
import os
import re
import ssl
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

from . import audit, db, status, sysmon, util, wipe

CAPTURE_UNIT = "noxy-capture.service"
NOXY_UNIT = "noxy.service"
AUDIT_CAP_BYTES = 10 * 50 * 1024 ** 2               # what `setup lab` configures (auditd.conf is root-only)
IPIFY = "https://api.ipify.org"
ACTIONS = {                                         # what the web UI may ask for; the CLI has the rest
    "noxy-restart": "restart noxy",
}


class ControlError(Exception):
    pass


# ------------------------------------------------------------------ command log

def log(con, source, action, command, exit_code, output="", seconds=0.0, python=False):
    con.execute("INSERT INTO command_log(ts, source, action, command, exit, output, seconds, python) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (util.now_ts(), source, action, command, exit_code, util.safe_text(output, 8000), round(seconds, 3),
                 1 if python else 0))
    con.commit()


def run_logged(con, source, action, cmd, timeout=60):
    t0 = time.monotonic()
    rc, out = util.run(cmd, timeout=timeout)
    log(con, source, action, " ".join(cmd), rc, out.strip(), time.monotonic() - t0)
    return rc, out


def command_log(con, limit=300):
    rows = [dict(r) for r in con.execute("SELECT * FROM command_log ORDER BY ts DESC LIMIT ?", (limit,))]
    return rows


def lab_event(con, kind, detail=""):
    con.execute("INSERT INTO lab_events(ts, kind, detail) VALUES(?,?,?)", (util.now_ts(), kind, detail))
    con.commit()


# ------------------------------------------------------------------ services

def under_systemd():
    """True when noxy runs as the systemd user service (restart and stop from the UI are possible)."""
    return bool(os.environ.get("INVOCATION_ID"))


def capture(con, verb, source="ui"):
    if verb not in ("start", "stop", "restart"):
        raise ControlError("unknown capture action")
    rc, out = run_logged(con, source, f"capture-{verb}", ["systemctl", "--no-ask-password", verb, CAPTURE_UNIT])
    if rc != 0:
        hint = ""
        if re.search(r"authenticat|Access denied|Interactive authentication", out, re.I):
            hint = (" The polkit rule from `sudo python3 noxy.py setup lab` (0.2.0 or later) is missing, or your "
                    "login hasn't picked up the noxy group yet (reboot).")
        raise ControlError((out.strip() or f"systemctl exited {rc}") + hint)
    if verb == "stop":
        lab_event(con, "capture_down", f"stopped from {source}")
    else:
        lab_event(con, "capture_up", f"{verb} from {source}")
    return {"ok": True, "output": out.strip()}


def noxy_service(con, verb, source="ui"):
    if verb not in ("restart", "stop"):
        raise ControlError("unknown action")
    if not under_systemd():
        raise ControlError("noxy runs in a terminal, not as the user service: stop it there with Ctrl+C.")
    log(con, source, f"noxy-{verb}", f"systemctl --user {verb} {NOXY_UNIT}", 0,
        "scheduled: noxy answers first, then systemd " + ("restarts" if verb == "restart" else "stops") + " it")

    def later():
        time.sleep(0.8)
        subprocess.Popen(["systemctl", "--user", verb, NOXY_UNIT], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    threading.Thread(target=later, daemon=True).start()
    return {"ok": True, "message": "Restarting: reload the page in a few seconds." if verb == "restart" else
            "Stopping. Start it again in a terminal: systemctl --user start noxy"}


# ------------------------------------------------------------------ capture retention and database

def prune(cfg, force=False):
    """Deletes capture files beyond retention or the size cap. Never files written in the last hour."""
    try:
        files = sorted(util.PCAP_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
    except OSError:
        return {"deleted": [], "freed": 0}
    now = util.now_ts()
    keep_s = cfg["pcap_retention_days"] * 86400
    max_b = cfg["pcap_max_gb"] * 1024 ** 3
    sizes = {}
    for p in files:
        try:
            sizes[p] = p.stat()
        except OSError:
            pass
    total = sum(st.st_size for st in sizes.values())
    deleted, freed = [], 0
    for p, st in sizes.items():
        if now - st.st_mtime < 3600:
            break
        if now - st.st_mtime > keep_s or total > max_b:
            try:
                p.unlink()
                total -= st.st_size
                freed += st.st_size
                deleted.append(p.name)
            except OSError:
                pass
    return {"deleted": deleted, "freed": freed}


def prune_logged(con, cfg, source="ui"):
    t0 = time.monotonic()
    r = prune(cfg)
    equiv = (f"find {util.PCAP_DIR} -name '*.pcap' -mmin +{cfg['pcap_retention_days'] * 1440} -delete"
             f"   # plus oldest-first deletion above {cfg['pcap_max_gb']} GB")
    log(con, source, "prune", equiv, 0, f"deleted {len(r['deleted'])} files, freed {util.human_bytes(r['freed'])}"
        + (": " + ", ".join(r["deleted"][:30]) if r["deleted"] else ""), time.monotonic() - t0, python=True)
    return r


def vacuum(con, source="ui"):
    before = db.path().stat().st_size
    t0 = time.monotonic()
    con.execute("VACUUM")
    after = db.path().stat().st_size
    log(con, source, "vacuum", f"sqlite3 {db.path()} 'VACUUM;'", 0,
        f"{util.human_bytes(before)} -> {util.human_bytes(after)}", time.monotonic() - t0, python=True)
    return {"before": before, "after": after}


# ------------------------------------------------------------------ disk

def _du(path):
    total, count = 0, 0
    try:
        for root, _dirs, files in os.walk(path, onerror=lambda e: None):
            for f in files:
                try:
                    total += os.lstat(os.path.join(root, f)).st_size
                    count += 1
                except OSError:
                    pass
    except OSError:
        pass
    return total, count


def _tilde(p):
    home = os.path.expanduser("~")
    p = str(p)
    return "~" + p[len(home):] if home not in ("", "/") and p.startswith(home + "/") else p


def disk(con):
    fs, seen = [], set()
    for label, p in (("system /", Path("/")), ("audit log", util.AUDIT_DIR), ("captures", util.PCAP_DIR),
                     ("noxy data", util.DATA)):
        try:
            st = os.statvfs(p)
            dev = os.stat(p).st_dev
        except OSError:
            continue
        if dev in seen:
            continue
        seen.add(dev)
        total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
        fs.append({"label": label, "path": str(p), "total": total, "free": free, "used": total - free})
    logs = audit.log_files()
    audit_size = 0
    for f in logs:
        try:
            audit_size += f.stat().st_size
        except OSError:
            pass
    from .ingest import earliest_record
    earliest = earliest_record(logs) if logs else None
    pcaps = []
    try:
        pcaps = sorted(util.PCAP_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
    except OSError:
        pass
    pc_size = 0
    for p in pcaps:
        try:
            pc_size += p.stat().st_size
        except OSError:
            pass
    oldest_pcap = None
    if pcaps:
        try:
            oldest_pcap = pcaps[0].stat().st_mtime
        except OSError:
            pass
    dbp = db.path()
    db_size = dbp.stat().st_size if dbp.exists() else 0
    for ext in ("-wal", "-shm"):
        try:
            db_size += Path(str(dbp) + ext).stat().st_size
        except OSError:
            pass
    sm_size = 0
    for f in sysmon.log_files():
        try:
            sm_size += f.stat().st_size
        except OSError:
            pass
    exports = _du(util.DATA / "exports")
    backups = _du(util.DATA / "backups")
    per_session = []
    for r in con.execute("SELECT s.id, s.name, s.started, (SELECT COUNT(*) FROM events e WHERE e.session_id=s.id) ev, "
                         "(SELECT COUNT(*) FROM net n WHERE n.session_id=s.id) nt FROM sessions s ORDER BY s.started DESC"):
        per_session.append({"id": r["id"], "name": r["name"], "started": r["started"], "events": r["ev"], "net": r["nt"],
                            "approx": r["ev"] * 450 + r["nt"] * 200})
    return {"filesystems": fs,
            "audit": {"size": audit_size, "cap": AUDIT_CAP_BYTES, "files": len(logs), "earliest": earliest},
            "captures": {"size": pc_size, "files": len(pcaps), "oldest": oldest_pcap},
            "database": {"size": db_size, "path": str(dbp)},
            "sysmon": {"size": sm_size, "path": str(sysmon.LOG)},
            "wipe": {"last": wipe.last_wipe(), "command": f"sudo python3 {_tilde(util.ROOT / 'noxy.py')} wipe",
                     "logs": sum(i["size"] for i in wipe.plan())},
            "exports": {"size": exports[0], "files": exports[1]}, "backups": {"size": backups[0], "files": backups[1]},
            "sessions": per_session}


# ------------------------------------------------------------------ public IP

class PublicIP:
    """Asks api.ipify.org for the address the internet sees. Only when online, at most every 10 minutes unless
    forced, and again whenever the egress changes (home IP <-> VPN)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.ip = None
        self.ts = None
        self.error = None
        self.egress_key = None

    def get(self, con, force=False, source="ui"):
        eg = status.egress()
        key = (eg["mode"], eg["iface"])
        with self.lock:
            if eg["mode"] == "offline":
                self.ip, self.error, self.egress_key = None, None, key
                return self.view(eg)
            fresh = self.ts and util.now_ts() - self.ts < 600 and key == self.egress_key
            if fresh and not force:
                return self.view(eg)
            t0 = time.monotonic()
            try:
                req = urllib.request.Request(IPIFY, headers={"User-Agent": "noxy", "Accept": "text/plain"})
                with urllib.request.urlopen(req, timeout=6, context=ssl.create_default_context()) as r:
                    body = r.read(64).decode("ascii", "replace").strip()
                if not re.fullmatch(r"[0-9a-fA-F:.]{3,45}", body) or not util.is_ip(body):
                    raise ValueError(f"unexpected answer: {body[:40]!r}")
                self.ip, self.error = body, None
                code, out = 0, body
            except Exception as e:                   # noqa: BLE001 - network errors of every kind
                self.ip, self.error = None, f"{type(e).__name__}: {e}"[:200]
                code, out = 1, self.error
            self.ts, self.egress_key = util.now_ts(), key
            log(con, source, "publicip", f"curl -s {IPIFY}", code, out, time.monotonic() - t0, python=True)
            return self.view(eg)

    def view(self, eg):
        return {"ip": self.ip, "ts": self.ts, "error": self.error, "egress": eg,
                "label": {"home": "home IP", "vpn": "VPN IP", "offline": "offline"}[eg["mode"]]}


# ------------------------------------------------------------------ capture state for coverage

def capture_watch(con, state):
    """Called by the heartbeat: records capture up/down transitions, including stops done in a terminal."""
    up = status.capture_running()
    if state.get("cap") is None:
        lab_event(con, "capture_up" if up else "capture_down", "seen at noxy start")
    elif up != state["cap"]:
        lab_event(con, "capture_up" if up else "capture_down", "seen by noxy")
    state["cap"] = up


def egress_watch(con, state):
    """Called by the heartbeat: records every egress change (home IP, VPN through which config, offline)."""
    label = status.egress()["label"]
    if state.get("egress") is not None and label != state["egress"]:
        lab_event(con, "egress", label)
    state["egress"] = label


def egress_changes(con, start, end):
    end = end or util.now_ts()
    return [dict(r) for r in con.execute("SELECT ts, detail FROM lab_events WHERE kind='egress' AND ts BETWEEN ? AND ? "
                                         "ORDER BY ts", (start, end))]


FIREWALL_TXT = util.PCAP_DIR.parent / "firewall.txt"
_fw = {"ts": 0, "data": None}


def parse_ufw(text):
    """`ufw status verbose` -> {status, logging, defaults, rules: [{to, action, direction, from, comment, v6}]}."""
    out = {"status": None, "logging": None, "defaults": {}, "rules": []}
    in_rules = False
    for line in text.splitlines()[:2000]:
        if line.startswith("Status:"):
            out["status"] = line.split(":", 1)[1].strip()
        elif line.startswith("Logging:"):
            out["logging"] = line.split(":", 1)[1].strip()
        elif line.startswith("Default:"):
            for m in re.finditer(r"(\w+) \((\w+)\)", line):
                out["defaults"][m.group(2)] = m.group(1)
        elif re.match(r"^--\s+-+\s+--", line):
            in_rules = True
        elif in_rules and line.strip():
            body, _, comment = line.partition(" # ")
            # split on the action, not on column spacing: long destinations push the columns together
            m = re.match(r"^(.*?)\s+((?:ALLOW|DENY|REJECT|LIMIT)(?: (?:IN|OUT|FWD))?)\s+(.*?)\s*$", body.strip())
            if not m:
                continue
            to, action, frm = m.group(1), m.group(2), m.group(3)
            v6 = "(v6)" in to or "(v6)" in frm
            direction = "out" if action.endswith(" OUT") else "in" if action.endswith(" IN") else ""
            out["rules"].append({"to": to.replace(" (v6)", ""), "action": action.split()[0].lower(), "direction": direction,
                                 "from": frm.replace(" (v6)", ""), "comment": comment.strip()[:120], "v6": v6})
    return out


def firewall(force=False):
    """The VM firewall as noxy can see it, from the snapshot service (`setup lab` installs it). Refreshed at most every 15 s."""
    if not force and _fw["data"] and time.time() - _fw["ts"] < 15:
        return _fw["data"]
    if not Path("/etc/systemd/system/noxy-firewall.service").exists():
        data = {"available": False, "error": "Run `sudo python3 noxy.py setup lab` once more to let noxy read the firewall rules."}
    else:
        rc, out = util.run(["systemctl", "--no-ask-password", "start", "noxy-firewall.service"], timeout=20)
        try:
            text = FIREWALL_TXT.read_text(errors="replace")
            data = parse_ufw(text)
            data.update(available=True, ts=FIREWALL_TXT.stat().st_mtime,
                        error=None if rc == 0 else f"snapshot not refreshed: {out.strip()[:200]}")
        except OSError as e:
            data = {"available": False, "error": f"Can't read {FIREWALL_TXT}: {e.strerror}. Reboot if you just ran setup lab."
                    if rc == 0 else f"Snapshot failed: {out.strip()[:200]}"}
    _fw.update(ts=time.time(), data=data)
    return data


def capture_gaps(con, start, end):
    """[(from, to)] when the capture was down inside [start, end], from noxy's records."""
    end = end or util.now_ts()
    rows = [dict(r) for r in con.execute("SELECT ts, kind FROM lab_events WHERE kind IN ('capture_up','capture_down') "
                                         "AND ts <= ? ORDER BY ts", (end,))]
    gaps, down = [], None
    for r in rows:
        if r["kind"] == "capture_down" and down is None:
            down = r["ts"]
        elif r["kind"] == "capture_up" and down is not None:
            if r["ts"] > start:
                gaps.append((max(down, start), r["ts"]))
            down = None
    if down is not None:
        gaps.append((max(down, start), end))
    return [g for g in gaps if g[1] > start and g[0] < end]
