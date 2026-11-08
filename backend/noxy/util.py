"""Small shared helpers: UTC time, paths, defanging, hashing, JSONC, safe text."""
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import unicodedata
from pathlib import Path

UTC = dt.timezone.utc
ROOT = Path(__file__).resolve().parents[2]          # the noxy folder (contains noxy.py)
DATA = Path(os.environ.get("NOXY_DATA") or (ROOT / "data"))
PCAP_DIR = Path(os.environ.get("NOXY_PCAP_DIR") or "/var/lib/noxy/pcap")
AUDIT_DIR = Path(os.environ.get("NOXY_AUDIT_DIR") or "/var/log/audit")
DEFAULT_PORT = 8669


def utcnow():
    return dt.datetime.now(UTC)


def now_ts():
    return utcnow().timestamp()


def iso(ts):
    """Epoch seconds -> '2026-11-07T09:31:12Z'."""
    if ts is None:
        return None
    return dt.datetime.fromtimestamp(float(ts), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def readable(ts):
    """'Nov 07, 17:12 UTC' for messages people read (the UI formats its own dates)."""
    if ts is None:
        return "?"
    return dt.datetime.fromtimestamp(float(ts), UTC).strftime("%b %d, %H:%M UTC")


def iso_ms(ts):
    return dt.datetime.fromtimestamp(float(ts), UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_time(value, now=None):
    """'15m', '2h', '1d' ago, or an ISO / 'YYYY-MM-DD HH:MM[:SS]' time taken as UTC. Returns epoch seconds."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    v = str(value).strip()
    m = re.fullmatch(r"(\d+)\s*([smhd])", v)
    if m:
        secs = int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
        return (now or now_ts()) - secs
    v = v.replace("Z", "+00:00").replace(" ", "T", 1)
    t = dt.datetime.fromisoformat(v)
    if t.tzinfo is None:
        t = t.replace(tzinfo=UTC)
    return t.timestamp()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_public_ip(s):
    try:
        return ipaddress.ip_address(s).is_global
    except ValueError:
        return False


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def defang_host(h):
    if not h:
        return h
    if ":" in h and is_ip(h):                       # IPv6: defang the last colon
        i = h.rfind(":")
        return h[:i] + "[:]" + h[i + 1:]
    i = h.rfind(".")
    return h if i < 0 else h[:i] + "[.]" + h[i + 1:]


def defang_url(u):
    if not u:
        return u
    u = re.sub(r"^http", "hxxp", u, flags=re.I)
    m = re.match(r"^([\w+.-]+://)([^/:?#\[]+|\[[^\]]+\])(.*)$", u)
    if not m:
        return u
    return m.group(1) + defang_host(m.group(2)) + m.group(3)


_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe_text(s, limit=4000):
    """Sample-derived text for terminals and reports: no control or bidi characters, bounded length."""
    if s is None:
        return ""
    s = str(s)
    s = "".join("�" if unicodedata.category(c) == "Cf" and c not in "‍" else c for c in s)
    s = _CTRL.sub(lambda m: f"\\x{ord(m.group()):02x}", s)
    return s if len(s) <= limit else s[:limit] + f"... [{len(s) - limit} more chars]"


def strip_jsonc(text):
    """Remove // and /* */ comments and trailing commas, respecting strings."""
    out, i, n, in_str, esc = [], 0, len(text), False, False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_jsonc(path):
    try:
        with open(path, errors="replace") as f:
            return json.loads(strip_jsonc(f.read()))
    except (OSError, ValueError):
        return None


def run(cmd, timeout=30, env=None):
    """Run a command (list form, never a shell). Returns (rc, output)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
