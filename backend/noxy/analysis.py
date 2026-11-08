"""Turns parsed evidence into answers: severity, explainable noise rules, process tree, verdict, beacons, IOCs."""
import json
import os
import re
import shutil
import sqlite3
import statistics
import tempfile
from pathlib import Path

from . import audit, util

INTERPRETERS = {"node", "nodejs", "python3", "perl", "ruby", "php", "java", "deno", "bun", "pwsh", "osascript"}
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "fish"}
NETTOOLS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "ftp", "tftp", "telnet", "busybox"}
BROWSERS = {"firefox", "firefox-bin", "chrome", "chromium", "chromium-browse", "brave", "Web Content", "Socket Process"}
NEVER_NOISE = INTERPRETERS | SHELLS | NETTOOLS
DESKTOP_PREFIXES = ("gsd-", "gnome-", "tracker", "localsearch", "xdg-", "dbus-", "at-spi", "ibus-", "pipewire",
                    "wireplumber", "pulseaudio", "evolution-", "goa-", "gvfs", "update-notifier", "systemd",
                    "snap", "packagekit", "unattended-upgr", "apt-", "dpkg", "run-parts", "ubuntu-advantage",
                    "fwupd", "colord", "cupsd", "polkit", "nautilus", "Xwayland", "gjs", "ldconfig", "lsb_release",
                    "vmtoolsd", "vmware-", "motd")
BENIGN_DOMAINS = ("ubuntu.com", "canonical.com", "snapcraft.io", "launchpad.net", "mozilla.org", "mozilla.net",
                  "mozilla.com", "firefox.com", "mozaws.net", "remnux.org", "quad9.net", "debian.org", "pypi.org",
                  "pythonhosted.org", "npmjs.org", "github.com", "githubusercontent.com", "ipify.org", "arpa")
SEV_ORDER = {"high": 0, "medium": 1, "info": 2}

NOISE_RULES = [
    ("noxy", "started by noxy itself"),
    ("vscode-internal", "VS Code's own helper processes (tasks and terminals it starts are never hidden)"),
    ("ts-typings", "VS Code TypeScript type acquisition: npm with --ignore-scripts in ~/.cache/typescript"),
    ("desktop", "desktop, update and VMware Tools services, and Python scripts installed with the OS in /usr"),
]


def base(exe):
    return os.path.basename(exe or "")


def _name(ev):
    b = base(ev.get("exe"))
    return b or (ev.get("comm") or "")


def norm(name):
    """'python3.12' -> 'python3', 'python3' -> 'python3'; keeps tool names comparable across versions."""
    m = re.fullmatch(r"(python|perl|ruby|php|node)[\d.]*", name or "")
    return {"python": "python3", "node": "node"}.get(m.group(1), m.group(1)) if m else name


# ------------------------------------------------------------------ classification

def _is_self(pid, ts, self_pids):
    return any(a - 1 <= ts <= b + 90 for a, b in self_pids.get(pid, ()))


def noise_rule(ev, self_pids, parents):
    """Returns a noise rule id or None.

    self_pids: pid -> [(started, last_seen)] of noxy server processes (time-bounded, so a reused pid is not hidden).
    parents: pid -> ppid from the session's executions.
    """
    ts = ev.get("ts") or 0
    pid = ev.get("pid")
    seen = set()
    while pid and pid not in seen and len(seen) < 64:
        if _is_self(pid, ts, self_pids):
            return "noxy"
        seen.add(pid)
        pid = parents.get(pid)
    if ev.get("ppid") and _is_self(ev["ppid"], ts, self_pids):
        return "noxy"
    name, exe, cmd = norm(_name(ev)), ev.get("exe") or "", ev.get("cmdline") or ""
    if ev.get("key") == "net" and ev.get("dest") in (f"127.0.0.1:{util.DEFAULT_PORT}", f"[::1]:{util.DEFAULT_PORT}"):
        return "noxy"                                  # the browser talking to noxy's own UI
    if "/noxy/noxy.py" in cmd or "/noxy/backend/" in cmd:
        return "noxy"
    if exe.startswith("/usr/share/code/") or exe.startswith("/snap/code/"):
        return "vscode-internal"
    if "/.cache/typescript/" in (ev.get("cwd") or "") and "--ignore-scripts" in cmd:
        return "ts-typings"
    if name == "python3" and re.match(r"^\S*python[\d.]*\s+(-\S+\s+)*/usr/(s?bin|lib|libexec|share)/", cmd):
        return "desktop"
    if name not in NEVER_NOISE and (name.startswith(DESKTOP_PREFIXES) or exe.startswith(("/usr/lib/apt/",
                                    "/usr/lib/update-notifier/", "/usr/libexec/", "/usr/lib/systemd/"))):
        return "desktop"
    return None


def classify_exec(ev):
    """Returns (severity, reason)."""
    cmd = ev.get("cmdline") or ""
    low = cmd.lower()
    name = norm(_name(ev))
    cwd = ev.get("cwd") or ""
    if re.search(r"(curl|wget)\b[^|]{0,400}\|\s*(sudo\s+)?(ba|da|z)?sh\b|(curl|wget)\b[^|]{0,400}\|\s*cmd\b", low) or \
            re.search(r"\bsh\s+-c\b.*(curl|wget)\b.*\|\s*(ba)?sh", low):
        return "high", "download piped straight into a shell"
    if re.search(r"/dev/(tcp|udp)/|\bnc(at)?\b.*\s-e\s|socat\b.*exec:|\bbash\s+-i\b", low):
        return "high", "reverse-shell pattern"
    if name in ("npm", "npx", "yarn", "pnpm", "bun") or re.search(r"\b(npm|npx|yarn|pnpm)(-cli\.js)?\b", low):
        if re.search(r"\b(install|i|ci|add|rebuild|exec|x)\b", low) and "--ignore-scripts" not in low \
                and "/.cache/typescript" not in cwd:
            return "high", f"package install that runs lifecycle scripts (in {cwd or '?'})"
        if re.search(r"\brun\b|\bstart\b|\btest\b", low):
            return "high", "npm script executed"
    if name in INTERPRETERS and re.search(r"\s-(e|c|-eval|-print)\s", f" {cmd} "):
        return "high", "inline code run by an interpreter"
    if re.search(r"\b(nohup|setsid|disown)\b", low) and re.search(r"\b(node|python3?|perl|sh|bash)\b", low):
        return "high", "detached background process"
    if re.search(r"start\s+/b\s+node|\bnode\s+server\b", low):
        return "high", "lure server started (node server)"
    if name == "crontab" and not re.search(r"\s-l\b", cmd):
        return "high", "crontab changed"
    if name == "systemctl" and re.search(r"--user\b.*\benable\b", low):
        return "high", "user service enabled"
    if name in ("node", "nodejs"):
        return "medium", "node executed"
    if name in NETTOOLS:
        return "medium", f"network tool {name}"
    if name == "base64" and re.search(r"\s-(d|-decode)\b", cmd):
        return "medium", "base64 decoding"
    if name == "chmod" and re.search(r"\+x|7[0-7][0-7]", cmd) and re.search(r"/(tmp|var/tmp|dev/shm)/", cmd):
        return "medium", "file made executable in a temp folder"
    if name in INTERPRETERS:
        return "medium", f"{name} executed"
    if name in ("git",) and re.search(r"\b(clone|fetch|pull|submodule)\b", low):
        return "info", "git network operation"
    return "info", ""


def classify_conn(ev):
    ip, port = audit.split_dest(ev.get("dest"))
    name = norm(_name(ev))
    if not ip:
        return "info", ""
    if ip.startswith("127.") or ip in ("::1", "0.0.0.0"):
        return "info", "loopback"
    if util.is_public_ip(ip):
        if name in INTERPRETERS | SHELLS | NETTOOLS:
            return "high", f"{name} connected to a public address"
        if name in BROWSERS or (ev.get("comm") or "") in BROWSERS:
            return "info", "browser"
        return "info", "public address"
    return "medium", "connection attempt to a private address"


def classify_watch(ev):
    name = _name(ev)
    if ev.get("key") == "persist" and any("/.ssh/" in p or p.endswith("/.ssh") for p in ev.get("paths") or []):
        return "high", f"SSH folder accessed by {name or '?'} (keys or known_hosts)"
    if ev.get("key") == "persist":
        return "high", f"persistence location written by {name or '?'}"
    if name in ("code", "electron") or (ev.get("exe") or "").startswith("/usr/share/code/"):
        return "info", "VS Code settings changed by VS Code"
    return "medium", f"VS Code settings changed by {name or '?'}"


# ------------------------------------------------------------------ session analysis

def load_self_pids(con, start, end):
    out = {}
    for r in con.execute("SELECT pid, started, last_seen FROM self_pids WHERE started <= ? AND last_seen >= ?",
                         (end or util.now_ts(), start - 120)):
        out.setdefault(r["pid"], []).append((r["started"], r["last_seen"]))
    return out


def execution(con, sid):
    s = con.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not s:
        return None
    start, end = s["started"], s["ended"]
    evs = [dict(r) for r in con.execute("SELECT * FROM events WHERE session_id=? ORDER BY ts, serial", (sid,))]
    self_pids = load_self_pids(con, start, end)
    execs = [e for e in evs if e["key"] == "exec"]
    parents = {}
    for e in execs:
        if e["pid"] and e["ppid"]:
            parents.setdefault(e["pid"], e["ppid"])
    findings = []
    procs = []
    for e in execs:
        e["paths"] = json.loads(e["paths"] or "[]")
        rule = noise_rule(e, self_pids, parents)
        sev, why = classify_exec(e)
        procs.append(_proc_view(e, sev, why, rule, start))
        if not rule and sev != "info":
            findings.append({"sev": sev, "ts": e["ts"], "what": why, "evidence": e["cmdline"][:300],
                             "pid": e["pid"], "kind": "exec"})
    conns = []
    for e in (x for x in evs if x["key"] == "net"):
        rule = noise_rule(e, self_pids, parents)
        sev, why = classify_conn(e)
        ip, port = audit.split_dest(e["dest"])
        conns.append({"ts": e["ts"], "iso": util.iso(e["ts"]), "rel": e["ts"] - start, "pid": e["pid"],
                      "name": _name(e), "dest": e["dest"], "ip": ip, "port": port, "public": util.is_public_ip(ip or ""),
                      "success": e["success"], "exit": e["exit"], "sev": sev, "why": why, "noise": rule})
        if not rule and sev != "info":
            findings.append({"sev": sev, "ts": e["ts"], "what": why, "evidence": f"{_name(e)} -> {e['dest']}",
                             "pid": e["pid"], "kind": "net"})
    watches = []
    for e in (x for x in evs if x["key"] in audit.WATCH_KEYS):
        rule = noise_rule(e, self_pids, parents)
        sev, why = classify_watch(e)
        paths = json.loads(e["paths"] or "[]")
        watches.append({"ts": e["ts"], "iso": util.iso(e["ts"]), "rel": e["ts"] - start, "pid": e["pid"],
                        "name": _name(e), "key": e["key"], "paths": paths, "sev": sev, "why": why, "noise": rule})
        if not rule and sev != "info":
            findings.append({"sev": sev, "ts": e["ts"], "what": why, "evidence": ", ".join(paths)[:300],
                             "pid": e["pid"], "kind": "watch"})
    artefacts = _ingest_info(con, sid, "artefacts") or {}
    for f in artefacts.get("findings", []):
        findings.append(f)
    fc = file_creations(con, sid, s=s, self_pids=self_pids)
    findings.extend(fc["findings"])
    coverage = _coverage(con, sid, s)
    findings = group_findings(findings)
    verdict = _verdict(findings, coverage, len(evs))
    return {"session": dict(s), "verdict": verdict, "coverage": coverage, "findings": findings,
            "processes": _tree(procs), "connections": _dedupe_conns(conns), "watches": watches,
            "artefacts": artefacts, "noise_rules": [{"id": i, "label": l} for i, l in NOISE_RULES],
            "counts": {"exec": len(execs), "net": len(conns), "watch": len(watches),
                       "suppressed": sum(1 for p in procs if p["noise"]), "files": fc["total"]},
            "histogram": _histogram([e["ts"] for e in execs], start, end or util.now_ts())}


def group_findings(findings):
    """One finding per (severity, what, evidence): first time, count. Sorted by severity, then time."""
    agg = {}
    for f in findings:
        k = (f["sev"], f["what"], f["evidence"])
        a = agg.get(k)
        if a:
            a["count"] += 1
            if f.get("ts") and (not a.get("ts") or f["ts"] < a["ts"]):
                a["ts"] = f["ts"]
        else:
            agg[k] = dict(f, count=1)
    out = sorted(agg.values(), key=lambda f: (SEV_ORDER[f["sev"]], f.get("ts") or 0))
    for f in out:
        f["iso"] = util.iso(f["ts"]) if f.get("ts") else None
    return out


def _proc_view(e, sev, why, rule, start):
    return {"ts": e["ts"], "iso": util.iso(e["ts"]), "rel": e["ts"] - start, "pid": e["pid"], "ppid": e["ppid"],
            "uid": e["uid"], "exe": e["exe"], "name": _name(e), "cmdline": e["cmdline"], "cwd": e["cwd"],
            "success": e["success"], "sev": sev, "why": why, "noise": rule}


def _tree(procs):
    """Orders executions as a forest. A re-exec of the same pid hangs under its previous image; otherwise a
    process hangs under the latest earlier execution of its ppid. Each item gets depth and a trail for drawing."""
    by_pid = {}
    children, roots = {}, []
    for p in procs:                                   # procs are in time order
        parent = None
        same = by_pid.get(p["pid"])
        if same:
            parent = same[-1]
        elif by_pid.get(p["ppid"]):
            parent = by_pid[p["ppid"]][-1]
        if parent is not None:
            children.setdefault(id(parent), []).append(p)
        else:
            roots.append(p)
        by_pid.setdefault(p["pid"], []).append(p)
    out = []
    stack = [(r, 0, []) for r in reversed(roots)]
    while stack:
        p, depth, trail = stack.pop()
        p["depth"], p["trail"] = depth, trail
        out.append(p)
        kids = children.get(id(p), [])
        for i in range(len(kids) - 1, -1, -1):
            stack.append((kids[i], depth + 1, trail + [i == len(kids) - 1]))
    return out


def _dedupe_conns(conns):
    """One row per (process name, destination): first time, attempts, worst severity."""
    agg = {}
    for c in conns:
        k = (c["name"], c["dest"], c["noise"])
        a = agg.get(k)
        if a:
            a["count"] += 1
            a["last"] = c["ts"]
            if SEV_ORDER[c["sev"]] < SEV_ORDER[a["sev"]]:
                a["sev"], a["why"] = c["sev"], c["why"]
        else:
            agg[k] = dict(c, count=1, last=c["ts"])
    return sorted(agg.values(), key=lambda c: c["ts"])


def _histogram(times, start, end, buckets=60):
    if end <= start:
        return {"start": start, "end": end, "bins": []}
    width = (end - start) / buckets
    bins = [0] * buckets
    for t in times:
        i = int((t - start) / width)
        if 0 <= i < buckets:
            bins[i] += 1
    return {"start": start, "end": end, "width": width, "bins": bins}


def _ingest_info(con, sid, source):
    r = con.execute("SELECT info FROM ingest WHERE session_id=? AND source=?", (sid, source)).fetchone()
    try:
        return json.loads(r["info"]) if r and r["info"] else None
    except ValueError:
        return None


def _coverage(con, sid, s):
    info = _ingest_info(con, sid, "audit") or {}
    marks = [dict(r) for r in con.execute("SELECT * FROM audit_marks WHERE session_id=? ORDER BY ts", (sid,))]
    gaps, notes = [], []
    from .control import egress_changes
    for e in egress_changes(con, s["started"], s["ended"]):
        notes.append(f"egress changed at {util.readable(e['ts'])}: now {e['detail']}")
    if not info:
        return {"state": "none", "text": "Not refreshed yet: press refresh to read the audit log.", "marks": marks, "notes": notes}
    if info.get("error"):
        return {"state": "unreadable", "text": info["error"], "marks": marks, "notes": notes}
    earliest = info.get("earliest")
    if earliest is None:
        return {"state": "empty", "text": "No audit records found: auditd is not running or has no rules loaded.",
                "marks": marks, "notes": notes}
    if earliest > s["started"] + 60:
        gaps.append(f"audit log starts {util.readable(earliest)}, after the session start (rotated or auditd started late)")
    down = None
    for m in marks:
        if m["kind"] in ("DAEMON_END", "DAEMON_ABORT"):
            down = m["ts"]
        elif m["kind"] == "DAEMON_START" and down:
            gaps.append(f"auditd was down from {util.readable(down)} to {util.readable(m['ts'])}")
            down = None
        elif m["kind"] == "CONFIG_CHANGE":
            notes.append(f"audit rules changed at {util.readable(m['ts'])}")
    if down:
        gaps.append(f"auditd stopped at {util.readable(down)} and did not restart")
    from .control import capture_gaps
    for a, b in capture_gaps(con, s["started"], s["ended"]):
        gaps.append(f"capture was down from {util.readable(a)} to {util.readable(b)}")
    if info.get("rules") is False:
        gaps.append("no exec/net records with noxy keys: are the noxy audit rules loaded? (noxy setup lab)")
    fi = _ingest_info(con, sid, "files") or {}
    if fi.get("error"):
        notes.append(fi["error"])
    elif fi.get("earliest") and fi["earliest"] > s["started"] + 60:
        notes.append(f"Sysmon log starts {util.readable(fi['earliest'])}, after the session start: earlier file "
                     "creations are not covered")
    state = "gaps" if gaps else "ok"
    text = "Audit and capture coverage complete for the session." if not gaps else "; ".join(gaps)
    return {"state": state, "text": text, "notes": notes, "marks": marks}


def _verdict(findings, coverage, n_events):
    high = sum(1 for f in findings if f["sev"] == "high")
    med = sum(1 for f in findings if f["sev"] == "medium")
    if high:
        return {"level": "suspicious", "title": f"Something ran: {high} high finding{'s' * (high != 1)}",
                "text": "Execution or persistence evidence below. Start from the first high finding."}
    if coverage["state"] in ("none", "unreadable", "empty"):
        return {"level": "unknown", "title": "Can't tell yet", "text": coverage["text"]}
    if med:
        return {"level": "review", "title": f"Review {med} finding{'s' * (med != 1)}",
                "text": "Nothing clearly malicious, but some activity needs reading in context."}
    if coverage["state"] == "gaps":
        return {"level": "unknown", "title": "Nothing seen, but coverage has gaps", "text": coverage["text"]}
    return {"level": "clean", "title": "Nothing ran", "text": f"No suspicious execution, connection or persistence "
            f"in {n_events} audit events with full coverage. Coffee's still warm."}


# ------------------------------------------------------------------ artefacts outside auditd

def artefacts(home, since, until):
    """npm logs, VS Code state, persistence items and new files in the session window. Read-only."""
    home = Path(home)
    until = until or util.now_ts()
    out = {"npm": [], "vscode": {}, "persistence": [], "files": [], "findings": []}

    def add(sev, what, evidence, ts=None):
        out["findings"].append({"sev": sev, "ts": ts, "what": what, "evidence": util.safe_text(evidence, 300),
                                "pid": None, "kind": "artefact"})

    for log in sorted((home / ".npm/_logs").glob("*-debug-*.log")):
        try:
            mt = log.stat().st_mtime
            if not since <= mt <= until + 60:
                continue
            text = log.read_text(errors="replace")[:200000]
        except OSError:
            continue
        argv = (re.search(r"verbose argv (.*)", text) or [None, "?"])[1]
        cwd = (re.search(r"verbose cwd (.*)", text) or [None, "?"])[1]
        ex = (re.search(r"verbose exit (.*)", text) or [None, "?"])[1]
        out["npm"].append({"ts": mt, "file": log.name, "argv": util.safe_text(argv, 400),
                           "cwd": util.safe_text(cwd, 300), "exit": ex})
        if "--ignore-scripts" not in argv and ".cache/typescript" not in cwd:
            add("high", "npm ran without --ignore-scripts", f"{argv} (cwd {cwd})", mt)
    settings = util.load_jsonc(home / ".config/Code/User/settings.json") or {}
    auto = settings.get("task.allowAutomaticTasks", "(not set)")
    out["vscode"]["automatic_tasks"] = auto
    if auto == "on":
        add("high", "VS Code automatic tasks are ON", "user settings.json")
    trusted = []
    db = home / ".config/Code/User/globalStorage/state.vscdb"
    if db.exists():
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td) / "state.vscdb"
            try:
                shutil.copy2(db, tmp)
                c = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
                rows = c.execute("SELECT value FROM ItemTable WHERE key LIKE '%trust%'").fetchall()
                c.close()
            except (OSError, sqlite3.Error):
                rows = []
        for (val,) in rows:
            try:
                info = json.loads(val)
            except (TypeError, ValueError):
                continue
            for u in (info or {}).get("uriTrustInfo", []) if isinstance(info, dict) else []:
                trusted.append({"path": util.safe_text((u.get("uri") or {}).get("fsPath") or str(u.get("uri")), 300),
                                "trusted": bool(u.get("trusted"))})
    out["vscode"]["trusted"] = trusted
    opened = []
    ws_root = home / ".config/Code/User/workspaceStorage"
    if ws_root.is_dir():
        for ws in ws_root.iterdir():
            try:
                if since <= ws.stat().st_mtime <= until + 60 and (ws / "workspace.json").exists():
                    opened.append(util.safe_text((ws / "workspace.json").read_text(errors="replace").strip(), 300))
            except OSError:
                pass
    out["vscode"]["opened"] = opened
    for o in opened:
        add("medium", "a folder was opened in VS Code during the session", o)
    for p in (home / ".config/autostart", home / ".config/systemd/user", home / ".ssh", Path("/etc/cron.d")):
        try:
            for f in p.iterdir():
                mt = f.lstat().st_mtime
                item = {"path": str(f), "ts": mt, "changed": since <= mt <= until + 60}
                out["persistence"].append(item)
                if item["changed"]:
                    add("high", "persistence item changed during the session", str(f), mt)
        except OSError:
            pass
    out["files"] = new_files(home, since, until)
    for f in out["files"]:
        if f["flag"]:
            add("medium", "new or changed executable or script", f["path"], f["ts"])
    return out


SKIP_DIRS = re.compile(r"/\.cache/|/\.mozilla/|/snap/|/\.config/Code/(Cache|CachedData|logs|GPUCache|Dawn\w*Cache|"
                       r"User/workspaceStorage|User/globalStorage|Local Storage|Service Worker)|/\.npm/_cacache/|"
                       r"/node-compile-cache/|/\.local/state/|/\.local/share/(gnome-shell|tracker|Trash)/|/noxy/data/|"
                       r"/noxy/\.previous-versions/")
SCRIPT_EXT = (".js", ".mjs", ".cjs", ".sh", ".py", ".pl", ".elf", ".so", ".bin", ".exe", ".desktop", ".service",
              ".timer", ".cmd", ".bat", ".ps1", ".vbs", ".jar")


TEMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")


def new_files(home, since, until, limit=400, budget=60000):
    rows, seen = [], 0
    for root in [Path(home)] + [Path(d) for d in TEMP_DIRS]:
        for dirpath, dirnames, files in os.walk(root, onerror=lambda e: None):
            if SKIP_DIRS.search(dirpath + "/"):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules")]
            for f in files:
                seen += 1
                if seen > budget:
                    rows.append({"path": "(file scan stopped after 60000 files)", "ts": None, "exec": False, "flag": False})
                    return rows
                p = os.path.join(dirpath, f)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if since <= st.st_mtime <= until + 60 and not SKIP_DIRS.search(p):
                    x = bool(st.st_mode & 0o111) and not os.path.islink(p)
                    flag = x or p.endswith(SCRIPT_EXT) or "/.ssh/" in p or p.endswith(("bashrc", "profile", "zshrc"))
                    rows.append({"path": util.safe_text(p, 400), "ts": st.st_mtime, "exec": x, "flag": flag})
    rows.sort(key=lambda r: r["ts"] or 0)
    return rows[:limit]


# ------------------------------------------------------------------ file creation (Sysmon)

FILE_NOISE_RULES = [
    ("noxy", "noxy's own database and the capture service's files"),
    ("browser", "the browser's profile, cache and shared-memory files (downloads stay visible)"),
    ("vscode-internal", "VS Code's own state, caches and temporary files"),
    ("desktop", "desktop, update and system services, and their caches and runtime files"),
]
PERSIST_FILE = re.compile(r"/\.config/(autostart|systemd/user)/|/\.(bashrc|profile|bash_profile|bash_login|zshrc|zprofile)$|"
                          r"/\.ssh/|/\.local/bin/|^/etc/(cron|crontab|systemd/system/|ld\.so\.preload|profile\.d/|"
                          r"xdg/autostart/|sudoers|rc\.local|environment)|^/var/spool/cron/|^/(usr/)?lib/systemd/system/")
BROWSER_PATHS = re.compile(r"/\.mozilla/|/\.cache/(mozilla|chromium|google-chrome|BraveSoftware)/|/snap/firefox/|"
                           r"/\.config/(chromium|google-chrome|BraveSoftware)/|^/dev/shm/(org\.mozilla|org\.chromium|\.org\.chromium)|"
                           r"^/tmp/(firefox|mozilla|Temp-|tmpaddon|\.org\.chromium)")
VSCODE_PATHS = re.compile(r"/\.config/Code/|/\.vscode/|^/tmp/vscode-|^/run/user/\d+/vscode-")
VSCODE_KEEP = re.compile(r"/\.config/Code/User/(settings|tasks|keybindings)\.json$")
DESKTOP_PATHS = re.compile(r"^/run/|/\.cache/(tracker3?|fontconfig|thumbnails|ibus|gstreamer-1\.0|mesa_shader_cache|"
                           r"gnome-software|evolution|ubuntu-report|motd\.legal-displayed|event-sound-cache)|"
                           r"/\.local/share/(recently-used\.xbel|gvfs-metadata|tracker|gnome-shell|keyrings|"
                           r"sounds|Trash/info)|/\.config/(dconf|pulse|ibus|gnome-session|nautilus|enchant|"
                           r"evolution|goa-1\.0|monitors\.xml)|/\.local/state/(wireplumber|gnome)|"
                           r"^/var/(cache|lib/(apt|dpkg|systemd|PackageKit|snapd|ubuntu-advantage|NetworkManager|dhcp|"
                           r"upower|colord|polkit-1|fwupd|update-notifier|AccountsService|gdm3|fprint|private|"
                           r"command-not-found|ucf|vmware))/|^/var/spool/(cups|anacron)/|^/tmp/\.X11-unix/|^/tmp/\.ICE-unix/|"
                           r"^/tmp/(systemd-private-|snap-private-tmp|tracker-extract|\.font-unix)")
TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
FILE_ROWS_CAP = 20000


def file_noise(f, self_pids):
    name, image, path = norm(base(f["image"])), f["image"] or "", f["path"] or ""
    if f["pid"] and _is_self(f["pid"], f["ts"], self_pids):
        return "noxy"
    if path.startswith((str(util.DATA) + "/", str(util.PCAP_DIR) + "/")) or "/noxy/.previous-versions/" in path:
        return "noxy"
    if (name in BROWSERS or "/firefox" in image or "/chrom" in image) and BROWSER_PATHS.search(path):
        return "browser"
    if image.startswith(("/usr/share/code/", "/snap/code/")) and VSCODE_PATHS.search(path) and not VSCODE_KEEP.search(path):
        return "vscode-internal"
    if name in NEVER_NOISE:
        return None
    if name.startswith(DESKTOP_PREFIXES) or image.startswith(("/usr/lib/systemd/", "/usr/libexec/", "/usr/lib/apt/",
                                                               "/usr/lib/update-notifier/", "/usr/lib/snapd/")):
        return "desktop"
    if DESKTOP_PATHS.search(path) and not PERSIST_FILE.search(path):
        return "desktop"
    return None


def classify_file(f, home=None):
    name, path = norm(base(f["image"])), f["path"] or ""
    who = name or "?"
    risky = name in INTERPRETERS | SHELLS | NETTOOLS
    script = path.lower().endswith(SCRIPT_EXT)
    temp = path.startswith(TEMP_PREFIXES)
    if PERSIST_FILE.search(path):
        return "high", f"persistence file created by {who}"
    if "/node_modules/" in path:
        return "info", "package files"
    if temp and risky and (script or "." not in os.path.basename(path)):
        return "high", f"script or binary dropped in a temp folder by {who}"
    if temp and risky:
        return "medium", f"file created in a temp folder by {who}"
    if script and risky:
        return "medium", f"script created by {who}"
    if risky and re.search(r"^/home/[^/]+/\.[^/]+$", path):
        return "medium", f"hidden file in the home folder created by {who}"
    if "/Downloads/" in path:
        return "info", "download"
    return "info", ""


def file_area(path):
    if path.startswith(TEMP_PREFIXES):
        return "temp"
    if path.startswith("/home/") or path.startswith("/root/"):
        return "home"
    if path.startswith(("/etc/", "/usr/", "/var/", "/opt/", "/lib", "/bin", "/sbin", "/boot/", "/srv/")):
        return "system"
    return "other"


def file_creations(con, sid, s=None, self_pids=None):
    s = s or con.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not s:
        return None
    start, end = s["started"], s["ended"]
    self_pids = self_pids if self_pids is not None else load_self_pids(con, start, end)
    rows, findings, agg = [], [], {}
    noise_counts = {}
    total = 0
    for r in con.execute("SELECT ts, pid, image, path, user FROM files WHERE session_id=? ORDER BY ts", (sid,)):
        f = dict(r)
        total += 1
        rule = file_noise(f, self_pids)
        sev, why = classify_file(f)
        f.update(name=base(f["image"]) or "?", noise=rule, sev=sev, why=why, area=file_area(f["path"]),
                 folder=os.path.dirname(f["path"]), rel=f["ts"] - start)
        if rule:
            noise_counts[rule] = noise_counts.get(rule, 0) + 1
        elif sev != "info":
            k = (sev, why, f["folder"])
            a = agg.get(k)
            if a:
                a["n"] += 1
            else:
                agg[k] = {"sev": sev, "what": why, "ts": f["ts"], "first": f["path"], "n": 1, "pid": f["pid"]}
        rows.append(f)
    for a in agg.values():
        ev = a["first"] if a["n"] == 1 else f"{a['first']} (and {a['n'] - 1} more in the same folder)"
        findings.append({"sev": a["sev"], "ts": a["ts"], "what": a["what"], "evidence": ev[:300], "pid": a["pid"],
                         "kind": "file"})
    if len(rows) > FILE_ROWS_CAP:
        keep = [f for f in rows if not f["noise"]][:FILE_ROWS_CAP]
        rows = sorted(keep + [f for f in rows if f["noise"]][:max(0, FILE_ROWS_CAP - len(keep))], key=lambda f: f["ts"])
    info = _ingest_info(con, sid, "files") or {}
    return {"session": dict(s), "rows": rows, "total": total, "shown": len(rows), "findings": group_findings(findings),
            "noise_rules": [{"id": i, "label": l, "count": noise_counts.get(i, 0)} for i, l in FILE_NOISE_RULES],
            "source": info, "histogram": _histogram([f["ts"] for f in rows if not f["noise"]], start, end or util.now_ts())}


# ------------------------------------------------------------------ network

def network(con, sid):
    s = con.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not s:
        return None
    start = s["started"]
    rows = [dict(r) for r in con.execute("SELECT * FROM net WHERE session_id=? ORDER BY ts", (sid,))]
    for r in rows:
        r["iso"] = util.iso(r["ts"])
        r["rel"] = r["ts"] - start
    by = {k: [r for r in rows if r["kind"] == k] for k in ("dns", "http", "tls", "syn", "udp")}
    dns = {}
    for r in by["dns"]:
        d = dns.get((r["name"], r["qtype"]))
        if d:
            d["count"] += 1
            d["last"] = r["ts"]
        else:
            dns[(r["name"], r["qtype"])] = dict(r, count=1, last=r["ts"], benign=_benign(r["name"]))
    flows = {}
    for r in by["syn"] + by["udp"]:
        proto = "tcp" if r["kind"] == "syn" else "udp"
        k = (proto, r["dst"], r["dport"])
        f = flows.get(k)
        n = r.get("count") or 1
        if f:
            f["count"] += n
            f["last"] = max(f["last"], r.get("last_ts") or r["ts"])
        else:
            flows[k] = {"proto": proto, "dst": r["dst"], "dport": r["dport"], "ts": r["ts"], "iso": r["iso"],
                        "rel": r["rel"], "count": n, "last": r.get("last_ts") or r["ts"], "public": util.is_public_ip(r["dst"])}
    findings = []
    for r in by["http"]:
        host = r["name"] or r["dst"]
        r["url"] = f"http://{host}{r['uri']}" if r["uri"].startswith("/") else r["uri"]
        r["raw_ip_host"] = util.is_ip((host or "").split(":")[0].strip("[]"))
        r["benign"] = _benign(host)
        if r["raw_ip_host"] and util.is_public_ip(r["dst"]):
            findings.append({"sev": "high", "ts": r["ts"], "what": "HTTP to a raw public IP", "evidence": r["url"][:300]})
        if re.search(r"[?&]\w*(env|process|info|data|sys)\w*=[^&]{200,}", r["uri"] or "", re.I):
            findings.append({"sev": "high", "ts": r["ts"], "what": "large data in the query string (exfiltration?)",
                             "evidence": r["url"][:300]})
    for f in flows.values():
        if f["public"] and f["dport"] not in (53, 80, 443, 853, 123):
            findings.append({"sev": "medium", "ts": f["ts"], "what": f"{f['proto'].upper()} to a non-standard port",
                             "evidence": f"{f['dst']}:{f['dport']} x{f['count']}"})
    beacons = detect_beacons(by["http"], by["syn"])
    for b in beacons:
        findings.append({"sev": "high", "ts": b["first"], "what": f"periodic traffic every ~{b['interval']:.1f}s",
                         "evidence": f"{b['target']} x{b['count']} (jitter {b['jitter']:.0f}%)"})
    findings = group_findings(findings)
    info = _ingest_info(con, sid, "pcap") or {}
    return {"session": dict(s), "findings": findings, "dns": sorted(dns.values(), key=lambda d: d["ts"]),
            "http": by["http"], "tls": _first_per(by["tls"], ("name", "dst", "dport")),
            "flows": sorted(flows.values(), key=lambda f: f["ts"]), "beacons": beacons,
            "capture": info, "histogram": _histogram([r["ts"] for r in rows if r["kind"] != "udp"], start,
                                                     s["ended"] or util.now_ts())}


def _first_per(rows, keys):
    seen = {}
    for r in rows:
        k = tuple(r[x] for x in keys)
        if k in seen:
            seen[k]["count"] += 1
        else:
            seen[k] = dict(r, count=1)
    return list(seen.values())


def _benign(host):
    h = (host or "").lower().rstrip(".").split(":")[0]
    return any(h == d or h.endswith("." + d) for d in BENIGN_DOMAINS)


def detect_beacons(http_rows, syn_rows, min_count=4, max_jitter=0.25):
    groups = {}
    for r in http_rows:
        path = (r["uri"] or "").split("?", 1)[0]
        groups.setdefault(("http", f"{r['method']} {r['name'] or r['dst']}{path}"), []).append(r["ts"])
    for r in syn_rows:
        if util.is_public_ip(r["dst"]):
            groups.setdefault(("tcp", f"{r['dst']}:{r['dport']}"), []).append(r["ts"])
    out = []
    for (kind, target), times in groups.items():
        times.sort()
        if len(times) < min_count:
            continue
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0.05]
        if len(gaps) < min_count - 1:
            continue
        med = statistics.median(gaps)
        if med < 0.5:
            continue
        mad = statistics.median(abs(g - med) for g in gaps)
        jitter = mad / med if med else 1
        if jitter <= max_jitter:
            out.append({"kind": kind, "target": target, "count": len(times), "interval": med,
                        "jitter": jitter * 100, "first": times[0], "last": times[-1]})
    return sorted(out, key=lambda b: b["first"])


# ------------------------------------------------------------------ indicators

def indicators(con, sid):
    n = network(con, sid)
    x = execution(con, sid)
    if not n or not x:
        return None
    iocs = {}

    def add(kind, value, ts, source, benign=False):
        if not value:
            return
        k = (kind, value)
        i = iocs.get(k)
        if i:
            i["count"] += 1
            i["first"] = min(i["first"], ts)
            i["last"] = max(i["last"], ts)
            i["sources"].add(source)
        else:
            iocs[k] = {"type": kind, "value": value, "first": ts, "last": ts, "count": 1, "sources": {source},
                       "benign": benign}
    for d in n["dns"]:
        if not d["name"].endswith((".arpa", ".local")):
            for _ in range(d["count"]):
                add("domain", d["name"], d["ts"], "dns", d["benign"])
    for h in n["http"]:
        host = (h["name"] or "").split(":")[0]
        add("url", h["url"], h["ts"], "http", h["benign"])
        if host and not util.is_ip(host.strip("[]")):
            add("domain", host.lower(), h["ts"], "http", h["benign"])
    for t in n["tls"]:
        add("domain", t["name"], t["ts"], "tls", _benign(t["name"]))
    for f in n["flows"]:
        if f["public"]:
            add("ip", f["dst"], f["ts"], f["proto"])
    for c in x["connections"]:
        if c["public"] and not c["noise"]:
            add("ip", c["ip"], c["ts"], "audit")
    out = []
    for i in iocs.values():
        i["sources"] = sorted(i["sources"])
        i["defanged"] = util.defang_url(i["value"]) if i["type"] == "url" else util.defang_host(i["value"])
        i["first_iso"], i["last_iso"] = util.iso(i["first"]), util.iso(i["last"])
        out.append(i)
    order = {"url": 0, "domain": 1, "ip": 2}
    return sorted(out, key=lambda i: (i["benign"], order[i["type"]], i["first"]))
