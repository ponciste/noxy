"""Local HTTP server: 127.0.0.1 only, per-launch token on every API call, strict CSP, no login by design.

Threat model for the UI: everything noxy shows comes from attacker-controlled input, and any page open in the
VM's browser (a phishing page, say) can send requests to 127.0.0.1. So:
  - the Host header must be noxy's own address (blocks DNS rebinding);
  - every /api/ call needs the per-launch token in a custom header, which another origin can neither read nor
    send without a CORS preflight that noxy never approves;
  - state-changing calls also need a matching Origin when the browser sends one;
  - responses carry a strict CSP and are never cached; the frontend renders sample text with textContent only.
"""
import csv
import io
import json
import os
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from . import VERSION, analysis, audit, backup, commands, control, db, ingest, sessions, status, util, vpn

FRONTEND = util.ROOT / "frontend"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
STATIC_TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml",
                ".woff2": "font/woff2", ".png": "image/png", ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8"}
MAX_BODY = 64 * 1024
CONFIG_DEFAULTS = {"pcap_retention_days": 7, "pcap_max_gb": 5}


def load_config():
    cfg = dict(CONFIG_DEFAULTS)
    try:
        cfg.update(json.loads((util.DATA / "config.json").read_text()))
    except (OSError, ValueError):
        pass
    return cfg


def static_map():
    m = {}
    assets = FRONTEND / "assets"
    for p in assets.rglob("*"):
        if p.is_file() and p.suffix in STATIC_TYPES and not p.is_symlink():
            m["/assets/" + p.relative_to(assets).as_posix()] = p
    return m


class App:
    def __init__(self, port):
        self.port = port
        self.token = secrets.token_urlsafe(32)
        self.hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        self.origins = {f"http://{h}" for h in self.hosts}
        self.static = static_map()
        self.refresh_lock = threading.Lock()
        self.started = util.now_ts()
        self.cfg = load_config()
        self.public_ip = control.PublicIP()
        self.cap_state = {}


class Handler(BaseHTTPRequestHandler):
    server_version = "noxy"
    sys_version = ""
    app = None                                       # set in serve()

    def log_message(self, fmt, *args):               # quiet: errors only, via log_error
        pass

    def log_error(self, fmt, *args):
        sys.stderr.write("noxy: " + (fmt % args) + "\n")

    # ---------------------------------------------------------------- plumbing
    def _send(self, code, body=b"", ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), clipboard-read=()")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _err(self, code, msg):
        self._send(code, {"error": msg})

    def _host_ok(self):
        return (self.headers.get("Host") or "").lower() in self.app.hosts

    def _api_ok(self, state_changing):
        tok = self.headers.get("X-Noxy-Token") or ""
        if not secrets.compare_digest(tok, self.app.token):
            return False
        origin = self.headers.get("Origin")
        if state_changing and origin is not None and origin not in self.app.origins:
            return False
        site = self.headers.get("Sec-Fetch-Site")
        if site and site not in ("same-origin", "none"):
            return False
        return True

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("request too large")
        if n and not (self.headers.get("Content-Type") or "").startswith("application/json"):
            raise ValueError("JSON only")
        raw = self.rfile.read(n) if n else b"{}"
        data = json.loads(raw or b"{}")
        if not isinstance(data, dict):
            raise ValueError("JSON object expected")
        return data

    # ---------------------------------------------------------------- verbs
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self._host_ok():
            return self._err(421, "wrong host")
        url = urlsplit(self.path)
        p = unquote(url.path)
        if p in ("/", "/index.html"):
            html = (FRONTEND / "index.html").read_text().replace("{{NOXY_TOKEN}}", self.app.token)
            html = html.replace("{{NOXY_VERSION}}", VERSION)
            return self._send(200, html, "text/html; charset=utf-8")
        if p == "/favicon.ico":
            p = "/assets/img/favicon.svg"
        if p in self.app.static:
            f = self.app.static[p]
            return self._send(200, f.read_bytes(), STATIC_TYPES[f.suffix], {"Cache-Control": "no-cache"})
        if p.startswith("/api/"):
            if not self._api_ok(False):
                return self._err(403, "forbidden")
            return self._route("GET", p, parse_qs(url.query))
        return self._err(404, "not found")

    def do_POST(self):
        self._mutate("POST")

    def do_DELETE(self):
        self._mutate("DELETE")

    def _mutate(self, verb):
        if not self._host_ok():
            return self._err(421, "wrong host")
        p = unquote(urlsplit(self.path).path)
        if not p.startswith("/api/") or not self._api_ok(True):
            return self._err(403, "forbidden")
        try:
            body = self._body()
        except (ValueError, json.JSONDecodeError) as e:
            return self._err(400, str(e))
        return self._route(verb, p, {}, body)

    # ---------------------------------------------------------------- routes
    def _route(self, verb, p, q, body=None):
        con = db.connect()
        try:
            return self._dispatch(con, verb, p, q, body or {})
        except (sessions.SessionError, control.ControlError) as e:
            return self._err(400, str(e))
        except (KeyError, ValueError) as e:
            return self._err(400, f"bad request: {e}")
        except Exception as e:                       # never leak a traceback to the page
            self.log_error("internal error on %s %s: %r", verb, p, e)
            return self._err(500, "internal error (see journalctl --user -u noxy)")
        finally:
            con.close()

    def _dispatch(self, con, verb, p, q, body):
        m = re.fullmatch(r"/api/sessions/(\d+)(/[a-z.]+)?(/\d+)?", p)
        sid = int(m.group(1)) if m else None
        sub = (m.group(2) or "") if m else None
        if verb == "GET":
            if p == "/api/status":
                st = status.checks()
                st.update(version=VERSION, session=sessions.current(con), now=util.now_ts(), vpn=vpn.state(),
                          audit_rate=audit.growth_rate(), uptime=util.now_ts() - self.app.started)
                return self._send(200, st)
            if p == "/api/pulse":
                cur = sessions.current(con)
                return self._send(200, {"now": util.now_ts(), "audit_rate": audit.growth_rate(),
                                        "egress": status.egress(), "session": cur,
                                        "restartable": control.under_systemd(), "version": VERSION})
            if p == "/api/sessions":
                return self._send(200, {"sessions": sessions.listing(con), "current": sessions.current(con)})
            if p == "/api/publicip":
                return self._send(200, self.app.public_ip.get(con, force=q.get("refresh") == ["1"]))
            if p == "/api/console":
                return self._send(200, {"log": control.command_log(con), "under_systemd": control.under_systemd(),
                                        "capture": status.capture_running(), "actions": control.ACTIONS,
                                        "config": self.app.cfg})
            if p == "/api/disk":
                return self._send(200, control.disk(con))
            if p == "/api/commands":
                topic = (q.get("topic") or ["all"])[0]
                ses, files = None, None
                if q.get("session") and q["session"][0].isdigit():
                    ses = sessions.get(con, int(q["session"][0]))
                    info = analysis._ingest_info(con, ses["id"], "pcap") or {}
                    files = sorted((info.get("files") or {}).keys())
                return self._send(200, {"topics": commands.recipes(topic, ses, files)})
            if m and sub == "/stats":
                return self._send(200, session_stats(con, sid))
            if m and sub == "":
                return self._send(200, sessions.get(con, sid))
            if m and sub == "/exec":
                return self._send(200, analysis.execution(con, sid) or {})
            if p == "/api/firewall":
                return self._send(200, control.firewall(force=q.get("refresh") == ["1"]))
            if m and sub == "/files":
                return self._send(200, analysis.file_creations(con, sid) or {})
            if m and sub == "/net":
                return self._send(200, analysis.network(con, sid) or {})
            if m and sub == "/iocs":
                return self._send(200, {"iocs": analysis.indicators(con, sid) or []})
            if m and sub == "/iocs.csv":
                return self._send(200, iocs_csv(con, sid), "text/csv; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="noxy-session-{sid}-iocs.csv"'})
            if m and sub == "/notes":
                return self._send(200, {"notes": sessions.notes(con, sid)})
            em = re.fullmatch(r"/api/exports/(noxy-export-\d{8}T\d{6}Z\.zip)", p)
            if em:
                f = util.DATA / "exports" / em.group(1)
                if not f.is_file():
                    return self._err(404, "no such export")
                return self._send(200, f.read_bytes(), "application/zip",
                                  {"Content-Disposition": f'attachment; filename="{em.group(1)}"'})
            return self._err(404, "not found")
        if verb == "POST":
            if p == "/api/sessions":
                new = sessions.start(con, body.get("name"), body.get("at") or None, body.get("tags") or "")
                return self._send(201, sessions.get(con, new))
            if m and sub == "/end":
                sessions.end(con, sid)
                return self._send(200, sessions.get(con, sid))
            if m and sub == "/notes":
                nid = sessions.add_note(con, sid, body.get("text"))
                return self._send(201, {"id": nid})
            if m and sub == "/refresh":
                if not self.app.refresh_lock.acquire(timeout=1):
                    return self._err(409, "a refresh is already running")
                try:
                    t0 = time.monotonic()
                    out = ingest.refresh(con, sid)
                    out["seconds"] = round(time.monotonic() - t0, 2)
                finally:
                    self.app.refresh_lock.release()
                return self._send(200, out)
            if p == "/api/export":
                return self._send(201, backup.export())
            if p == "/api/control":
                return self._send(200, run_control(self.app, con, str(body.get("action") or "")))
            return self._err(404, "not found")
        if verb == "DELETE":
            if p == "/api/sessions":
                if body.get("confirm") != "delete all":
                    return self._err(400, "confirmation missing")
                try:
                    return self._send(200, {"deleted": sessions.purge(con)})
                except sessions.SessionError as e:
                    return self._err(409, str(e))
            if m and sub == "/notes" and m.group(3):
                sessions.delete_note(con, sid, int(m.group(3)[1:]))
                return self._send(200, {"ok": True})
            if m and sub == "" and body.get("confirm") == f"delete {sid}":
                sessions.delete(con, sid)
                return self._send(200, {"ok": True})
            return self._err(400, "confirmation missing")
        return self._err(405, "method not allowed")


def iocs_csv(con, sid):
    rows = analysis.indicators(con, sid) or []
    s = sessions.get(con, sid)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "defanged", "first_seen_utc", "last_seen_utc", "count", "sources", "common_infra",
                "session"])
    for i in rows:
        w.writerow([i["type"], _csv_safe(i["value"]), _csv_safe(i["defanged"]), i["first_iso"], i["last_iso"],
                    i["count"], " ".join(i["sources"]), "yes" if i["benign"] else "no", _csv_safe(s["name"])])
    return buf.getvalue()


def _csv_safe(v):
    """Stop spreadsheet formula injection from sample-derived values."""
    v = util.safe_text(v, 4000)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def run_control(app, con, action):
    """The web UI can only restart noxy. Capture control, pruning and the rest stay in the CLI."""
    if action == "noxy-restart":
        return control.noxy_service(con, "restart")
    raise control.ControlError("unknown action")


def session_stats(con, sid):
    x = analysis.execution(con, sid)
    n = analysis.network(con, sid)
    if not x or not n:
        return {}
    s = x["session"]
    end = s["ended"] or util.now_ts()
    au = analysis._ingest_info(con, sid, "audit") or {}
    ing = {r["source"]: r["last_run"] for r in con.execute("SELECT source, last_run FROM ingest WHERE session_id=?", (sid,))}
    fc = analysis.file_creations(con, sid) or {"rows": [], "total": 0, "histogram": None}
    sev = {"high": 0, "medium": 0, "info": 0}
    for f in x["findings"] + n["findings"]:
        sev[f["sev"]] += 1
    return {"session": s, "duration": end - s["started"], "refreshed": max(ing.values()) if ing else None,
            "exec": x["counts"], "verdict": x["verdict"], "coverage": x["coverage"], "findings": sev,
            "audit": {"parsed": au.get("parsed"), "earliest": au.get("earliest"), "files": len(au.get("files") or [])},
            "net": {"dns": len(n["dns"]), "http": len(n["http"]), "tls": len(n["tls"]), "flows": len(n["flows"]),
                    "beacons": len(n["beacons"]),
                    "packets": (n.get("capture") or {}).get("packets", 0),
                    "capture_files": len((n.get("capture") or {}).get("files") or {})},
            "files": {"total": fc["total"], "noise": sum(1 for f in fc["rows"] if f["noise"]),
                      "flagged": sum(1 for f in fc["rows"] if not f["noise"] and f["sev"] != "info")},
            "histograms": {"exec": x["histogram"], "net": n["histogram"], "files": fc["histogram"]},
            "audit_rate": audit.growth_rate(),
            "notes": con.execute("SELECT COUNT(*) FROM notes WHERE session_id=?", (sid,)).fetchone()[0]}


def heartbeat(app):
    pid, started = os.getpid(), util.now_ts()
    last_hk = 0
    while True:
        try:
            con = db.connect()
            con.execute("INSERT INTO self_pids(pid, started, last_seen, role) VALUES(?,?,?, 'server') "
                        "ON CONFLICT(pid, started) DO UPDATE SET last_seen=excluded.last_seen",
                        (pid, started, util.now_ts()))
            con.commit()
            control.capture_watch(con, app.cap_state)
            control.egress_watch(con, app.cap_state)
            if time.time() - last_hk > 3600:
                r = control.prune(app.cfg)
                if r["deleted"]:
                    control.log(con, "auto", "prune", f"retention: delete captures older than {app.cfg['pcap_retention_days']} "
                                f"days or beyond {app.cfg['pcap_max_gb']} GB", 0,
                                f"deleted {len(r['deleted'])} files, freed {util.human_bytes(r['freed'])}", python=True)
                last_hk = time.time()
            con.close()
        except Exception as e:                       # the heartbeat must survive anything
            sys.stderr.write(f"noxy: heartbeat failed: {e!r}\n")
        time.sleep(30)


def serve(port=util.DEFAULT_PORT):
    db.init()
    app = App(port)
    Handler.app = app
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        sys.exit(f"Cannot listen on 127.0.0.1:{port}: {e}. Is noxy already running? (systemctl --user status noxy)")
    httpd.daemon_threads = True
    threading.Thread(target=heartbeat, args=(app,), daemon=True).start()
    print(f"noxy {VERSION} running at http://127.0.0.1:{port}/  (Ctrl+C to stop)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
