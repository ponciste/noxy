"""Raw audit.log parser (no ausearch needed): executions, connections, watched-file writes, daemon marks."""
import ipaddress
import os
import re
from pathlib import Path

from . import util

LINE_RE = re.compile(r"type=(\w+) msg=audit\((\d+\.\d+):(\d+)\):\s?(.*)")
FIELD_RE = re.compile(r'([\w\[\]]+)=("([^"]*)"|\S+)')
HEX_FIELDS = re.compile(r"a\d+(\[\d+\])?|proctitle|name|cwd|exe|comm")
MARK_TYPES = {"DAEMON_START": "auditd started", "DAEMON_END": "auditd stopped", "DAEMON_ABORT": "auditd aborted",
              "DAEMON_ROTATE": "audit log rotated", "CONFIG_CHANGE": "audit rules changed",
              "DAEMON_RESUME": "auditd resumed", "EOE": None}
SYSCALLS = {("c000003e", "59"): "execve", ("c000003e", "322"): "execveat", ("c000003e", "42"): "connect",
            ("40000003", "11"): "execve", ("40000003", "358"): "execveat", ("40000003", "362"): "connect",
            ("40000003", "102"): "socketcall"}
WATCH_KEYS = ("persist", "editor")


def _value(key, raw, quoted):
    if raw.startswith('"'):
        return quoted
    if HEX_FIELDS.fullmatch(key) and raw != "(null)" and len(raw) % 2 == 0 and len(raw) >= 2 \
            and re.fullmatch(r"[0-9A-Fa-f]+", raw):
        try:
            return bytes.fromhex(raw).replace(b"\x00", b" ").decode("utf-8", "replace").rstrip()
        except ValueError:
            pass
    return raw


def decode_saddr(saddr):
    """Hex sockaddr from a SOCKADDR record -> 'ip:port' / '[ip6]:port', or None for non-inet families."""
    if not saddr or len(saddr) < 8 or not re.fullmatch(r"[0-9A-Fa-f]+", saddr):
        return None
    family = int(saddr[2:4] + saddr[0:2], 16)
    port = int(saddr[4:8], 16)
    try:
        if family == 2 and len(saddr) >= 16:
            ip = str(ipaddress.IPv4Address(bytes.fromhex(saddr[8:16])))
            return f"{ip}:{port}"
        if family == 10 and len(saddr) >= 48:
            ip = ipaddress.IPv6Address(bytes.fromhex(saddr[16:48]))
            if ip.ipv4_mapped:
                return f"{ip.ipv4_mapped}:{port}"
            return f"[{ip.compressed}]:{port}"
    except ValueError:
        return None
    return None


def split_dest(dest):
    """'1.2.3.4:80' or '[::1]:80' -> (ip, port)."""
    if not dest:
        return None, None
    if dest.startswith("["):
        ip, _, port = dest[1:].partition("]:")
    else:
        ip, _, port = dest.rpartition(":")
    return ip, int(port) if port.isdigit() else None


def log_files(audit_dir=None):
    d = Path(audit_dir or util.AUDIT_DIR)
    files = list(d.glob("audit.log*"))

    def order(p):
        m = re.search(r"\.(\d+)$", p.name)
        return -(int(m.group(1)) if m else 0)          # oldest (highest suffix) first
    return sorted(files, key=order)


def _cmdline(args):
    """Readable, unambiguous command line: plain words as-is, anything else in double quotes with \\ and \" escaped."""
    parts = [args[i] for i in sorted(args)]
    return " ".join(p if p and re.fullmatch(r"[\w@%+=:,./~-]+", p)
                    else '"' + p.replace("\\", "\\\\").replace('"', '\\"') + '"' for p in parts)


def parse(paths, since=None, until=None, settle=2.0):
    """Parse audit logs. Returns (events, marks). Raises PermissionError if a log is unreadable."""
    raw = {}
    marks = []
    newest_ok = util.now_ts() - settle
    for path in paths:
        try:
            if since and os.path.getmtime(path) < since:
                continue
        except OSError:
            continue
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                m = LINE_RE.search(line)
                if not m:
                    continue
                rtype, ts_s, serial, rest = m.groups()
                ts = float(ts_s)
                if (since and ts < since) or (until and ts > until) or ts > newest_ok:
                    continue
                rest = rest.split("\x1d", 1)[0]
                if rtype in MARK_TYPES:
                    if MARK_TYPES[rtype]:
                        marks.append({"ts": ts, "kind": rtype, "detail": MARK_TYPES[rtype]})
                    continue
                fields = {k: _value(k, r, q) for k, r, q in FIELD_RE.findall(rest)}
                ev = raw.setdefault((ts, serial), {"ts": ts, "serial": int(serial), "args": {}, "paths": []})
                if rtype == "SYSCALL":
                    arch, num = fields.get("arch", ""), fields.get("syscall", "")
                    ev.update(key=fields.get("key", "").strip('"'), syscall=SYSCALLS.get((arch, num), num),
                              success=fields.get("success"), exit=fields.get("exit"),
                              pid=_int(fields.get("pid")), ppid=_int(fields.get("ppid")),
                              uid=fields.get("uid"), auid=fields.get("auid"),
                              exe=fields.get("exe", ""), comm=fields.get("comm", ""))
                elif rtype == "EXECVE":
                    for k, v in fields.items():
                        mm = re.fullmatch(r"a(\d+)(?:\[(\d+)\])?", k)
                        if mm:
                            idx = int(mm.group(1))
                            if mm.group(2) is None:
                                ev["args"][idx] = v
                            else:
                                ev["args"][idx] = ev["args"].get(idx, "") + v
                elif rtype == "PROCTITLE":
                    ev["proctitle"] = fields.get("proctitle", "")
                elif rtype == "CWD":
                    ev["cwd"] = fields.get("cwd", "")
                elif rtype == "PATH":
                    if fields.get("nametype") != "PARENT":
                        ev["paths"].append(fields.get("name", ""))
                elif rtype == "SOCKADDR":
                    ev["dest"] = decode_saddr(fields.get("saddr", ""))
    events = []
    for ev in raw.values():
        if not ev.get("key"):
            continue
        ev["cmdline"] = _cmdline(ev["args"]) if ev["args"] else ev.get("proctitle", "")
        cwd = ev.get("cwd", "")
        ev["paths"] = [p if p.startswith("/") or not cwd else os.path.normpath(os.path.join(cwd, p))
                       for p in ev["paths"] if p and p != "(null)"]
        if ev["key"] == "net" and not ev.get("dest"):
            continue                                           # unix sockets and other families
        ev.pop("args", None)
        ev.pop("proctitle", None)
        events.append(ev)
    events.sort(key=lambda e: (e["ts"], e["serial"]))
    marks.sort(key=lambda m: m["ts"])
    return events, marks


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def growth_rate(audit_dir=None, state={}):
    """Approximate audit records per minute from the growth of audit.log since the previous call."""
    p = Path(audit_dir or util.AUDIT_DIR) / "audit.log"
    try:
        size = p.stat().st_size
    except OSError:
        return None
    now = util.now_ts()
    prev = state.get("prev")
    state["prev"] = (now, size)
    if not prev or now - prev[0] < 1 or size < prev[1]:
        return state.get("rate")
    rate = (size - prev[1]) / (now - prev[0]) * 60 / 220          # ~220 bytes per record
    state["rate"] = round(rate)
    return state["rate"]
