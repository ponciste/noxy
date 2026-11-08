#!/usr/bin/env python3
"""
noxy: analysis-lab companion for a single REMnux VM. Standard library only. All times UTC.

    sudo python3 noxy.py setup lab           one-time: auditd rules, capture service, noxy group (then log out/in)
    sudo python3 noxy.py setup sysmon        optional: Sysmon for Linux for file creation anywhere
    python3 noxy.py setup service            start noxy at login (systemd user service)
    python3 noxy.py serve                    run in the foreground instead
    python3 noxy.py status                   lab status in the terminal
    python3 noxy.py session start NAME [--at 15m]   open a session (optionally backdated)
    python3 noxy.py session note TEXT        add a timestamped note to the open session
    python3 noxy.py refresh                  read audit log and captures into the open session
    python3 noxy.py report [--session N]     verdict and findings in the terminal
    python3 noxy.py session end              close the open session
    python3 noxy.py session purge            delete all sessions and notes (raw logs untouched)
    sudo python3 noxy.py wipe [sysmon ...]   delete collected logs (all four by default); `wipe snapshot` before a snapshot
    sudo python3 noxy.py vpn install F...    install Proton WireGuard configs (noxy-us.conf -> us)
    sudo python3 noxy.py vpn on [us] | off   Proton with a kill switch; `vpn status` without sudo
    python3 noxy.py export [--dest DIR]      everything in one zip (captures excluded)
    python3 noxy.py import FILE.zip          restore an export (current database is kept as a backup)
    python3 noxy.py capture start|stop|restart   control the capture service (a stop is recorded as a coverage gap)
    python3 noxy.py disk                     disk usage of the lab and noxy's sources
    python3 noxy.py log                      commands noxy has run (command log)

Web UI: http://127.0.0.1:8669/
"""
import argparse
import os
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

from noxy import VERSION, analysis, backup, control, db, ingest, sessions, setup, status, util, vpn, wipe  # noqa: E402


def say(msg=""):
    print(msg, flush=True)


def need_session(con, sid):
    if sid:
        return sessions.get(con, sid)
    s = sessions.current(con)
    if not s:
        sys.exit("No open session. Start one with: python3 noxy.py session start NAME (or pass --session N)")
    return s


def cmd_status(_a):
    st = status.checks()
    marks = {"ok": "[ ok ]", "warn": "[warn]", "fail": "[FAIL]", "info": "[info]"}
    say(f"noxy {VERSION} lab status, {util.iso(util.now_ts())}\n")
    for c in st["checks"]:
        say(f"  {marks[c['state']]} {c['label']:<22} {util.safe_text(c['detail'], 120)}")
        if c["hint"] and c["state"] in ("warn", "fail", "info"):
            say(f"         -> {c['hint']}")
    s = st["summary"]
    say(f"\n{s['ok']} ok, {s['warn']} warn, {s['fail']} fail")


def cmd_vpn(a):
    if a.action == "install":
        if not a.args:
            sys.exit("Give the .conf files: sudo python3 noxy.py vpn install ~/Downloads/*.conf")
        vpn.install(a.args, keep=a.keep)
    elif a.action == "on":
        sys.exit(vpn.on(a.args[0] if a.args else None))
    elif a.action == "off":
        sys.exit(vpn.off())
    else:
        sys.exit(vpn.status_text())


def cmd_session(a):
    db.init()
    con = db.connect()
    try:
        if a.action == "start":
            sid = sessions.start(con, " ".join(a.text) or "session", a.at)
            s = sessions.get(con, sid)
            say(f"Session {sid} '{s['name']}' started {util.iso(s['started'])} (egress: {s['egress']})")
        elif a.action == "note":
            s = need_session(con, a.session)
            sessions.add_note(con, s["id"], " ".join(a.text))
            say(f"Noted in session {s['id']}.")
        elif a.action == "end":
            s = need_session(con, a.session)
            ingest.refresh(con, s["id"])
            sessions.end(con, s["id"])
            say(f"Session {s['id']} closed. Run `python3 noxy.py report --session {s['id']}` or open the web UI.")
        elif a.action == "purge":
            n = con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            if not a.yes:
                if input(f'Delete all {n} sessions with their evidence and notes, and the command log? Type "delete all": ').strip() != "delete all":
                    sys.exit("Nothing deleted.")
            say(f"Deleted {sessions.purge(con)} sessions. Raw logs are not touched: sudo python3 noxy.py wipe")
        elif a.action == "list":
            for s in sessions.listing(con):
                state = "open" if not s["ended"] else (s["verdict"] or "closed")
                say(f"  {s['id']:>4}  {s['started_iso']}  {int(s['duration'] // 60):>5} min  {state:<10}  {s['name']}")
    except sessions.SessionError as e:
        sys.exit(str(e))
    finally:
        con.close()


def cmd_refresh(a):
    db.init()
    con = db.connect()
    try:
        s = need_session(con, a.session)
        out = ingest.refresh(con, s["id"])
        au, pc = out["audit"], out["pcap"]
        say(f"Session {s['id']} refreshed.")
        say("  audit:   " + (au.get("error") or f"{au['parsed']} events parsed, {au['added']} new"))
        say("  capture: " + (pc.get("error") or f"{len(pc['files'])} files, {pc['packets']} packets"
                             + (f", {len(pc['errors'])} errors" if pc["errors"] else "")))
        say(f"  verdict: {out['verdict']['title']}")
    finally:
        con.close()


def cmd_report(a):
    db.init()
    con = db.connect()
    try:
        s = need_session(con, a.session)
        x = analysis.execution(con, s["id"])
        n = analysis.network(con, s["id"])
        say(f"Session {s['id']} '{util.safe_text(s['name'])}'  {util.iso(s['started'])} -> {util.iso(s['ended']) or 'open'}")
        say(f"Verdict: {x['verdict']['title']}\n  {x['verdict']['text']}")
        say(f"Coverage: {x['coverage']['text']}\n")
        allf = sorted(x["findings"] + n["findings"], key=lambda f: (analysis.SEV_ORDER[f["sev"]], f["ts"] or 0))
        if not allf:
            say("No findings.")
        for f in allf:
            say(f"  [{f['sev'].upper():6}] {util.iso(f['ts']) or '-':20}  {f['what']}")
            say(f"           {util.safe_text(f['evidence'], 200)}")
    finally:
        con.close()


def cmd_export(a):
    db.init()
    r = backup.export(a.dest)
    say(f"Exported {r['sessions']} sessions to {r['path']}\nSHA-256 {r['sha256']}")


def server_up(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def cmd_import(a):
    if server_up(a.port):
        sys.exit("noxy is running. Stop it first: systemctl --user stop noxy (start it again afterwards).")
    try:
        r = backup.import_(a.file)
    except (ValueError, OSError) as e:
        sys.exit(f"Import refused: {e}")
    say(f"Imported {r['sessions']} sessions." + (f" Previous database kept at {r['previous']}" if r["previous"] else ""))


def cmd_capture(a):
    db.init()
    con = db.connect()
    try:
        control.capture(con, a.verb, source="cli")
        say(f"capture: {a.verb} done (systemctl {a.verb} noxy-capture.service)")
    except control.ControlError as e:
        sys.exit(str(e))
    finally:
        con.close()


def cmd_disk(_a):
    db.init()
    con = db.connect()
    try:
        d = control.disk(con)
    finally:
        con.close()
    hb = util.human_bytes
    say("File systems:")
    for f in d["filesystems"]:
        say(f"  {f['label']:<12} {hb(f['free']):>10} free of {hb(f['total']):>10}  ({f['path']})")
    a, c = d["audit"], d["captures"]
    say(f"Audit log:    {hb(a['size'])} of {hb(a['cap'])} in {a['files']} files; oldest record {util.iso(a['earliest']) or '-'}")
    say(f"Captures:     {hb(c['size'])} in {c['files']} files; oldest {util.iso(c['oldest']) or '-'}")
    say(f"Database:     {hb(d['database']['size'])}  ({d['database']['path']})")
    say(f"Exports:      {hb(d['exports']['size'])} in {d['exports']['files']} files; backups {hb(d['backups']['size'])}")


def cmd_log(_a):
    db.init()
    con = db.connect()
    try:
        for r in reversed(control.command_log(con, 100)):
            say(f"  {util.iso(r['ts'])}  {r['source']:<4} exit {r['exit']}  {util.safe_text(r['command'], 160)}")
    finally:
        con.close()


def main():
    ap = argparse.ArgumentParser(prog="noxy.py", description="noxy analysis-lab companion. All times UTC.")
    ap.add_argument("--version", action="version", version=f"noxy {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", help="run the web UI in the foreground")
    p.add_argument("--port", type=int, default=util.DEFAULT_PORT)
    p.set_defaults(fn=lambda a: __import__("noxy.server", fromlist=["serve"]).serve(a.port))

    p = sub.add_parser("setup", help="lab setup (sudo) or the user service")
    p.add_argument("what", choices=["lab", "service", "sysmon"])
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--remove", action="store_true", help="service: remove it")
    p.add_argument("--user", help="lab: the account that will use noxy (default: the one running sudo)")
    p.add_argument("--port", type=int, default=util.DEFAULT_PORT)
    p.set_defaults(fn=lambda a: setup.lab(a.dry_run, a.user, a.port) if a.what == "lab"
                   else setup.sysmon_setup(a.dry_run) if a.what == "sysmon"
                   else setup.service(a.dry_run, a.remove, a.port))

    p = sub.add_parser("status", help="lab status")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("session", help="start, note, end or list sessions")
    p.add_argument("action", choices=["start", "note", "end", "list", "purge"])
    p.add_argument("--yes", action="store_true", help="purge: don't ask")
    p.add_argument("text", nargs="*")
    p.add_argument("--at", help="start: backdate, e.g. 15m, 2h or '2026-11-07 09:00' (UTC)")
    p.add_argument("--session", type=int)
    p.set_defaults(fn=cmd_session)

    p = sub.add_parser("refresh", help="read audit log and captures into the session")
    p.add_argument("--session", type=int)
    p.set_defaults(fn=cmd_refresh)

    p = sub.add_parser("report", help="verdict and findings in the terminal")
    p.add_argument("--session", type=int)
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("export", help="everything in one zip (captures excluded)")
    p.add_argument("--dest")
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("import", help="restore an export")
    p.add_argument("file")
    p.add_argument("--port", type=int, default=util.DEFAULT_PORT)
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("capture", help="start, stop or restart the capture service")
    p.add_argument("verb", choices=["start", "stop", "restart"])
    p.set_defaults(fn=cmd_capture)

    p = sub.add_parser("vpn", help="Proton VPN with a kill switch: install, on, off, status (sudo, except status)")
    p.add_argument("action", choices=["install", "on", "off", "status"])
    p.add_argument("args", nargs="*", help="install: the .conf files; on: the config name (e.g. us)")
    p.add_argument("--keep", action="store_true", help="install: don't shred the original files")
    p.set_defaults(fn=cmd_vpn)

    p = sub.add_parser("wipe", help="delete collected logs and start fresh (sudo); targets: audit captures sysmon journal "
                       "noxy history temp, 'all' (default: the four logs) or 'snapshot' (everything)")
    p.add_argument("targets", nargs="*", help="audit, captures, sysmon, journal, noxy, history, temp, all, snapshot")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--poweroff", action="store_true", help="shut the VM down afterwards (for a clean snapshot)")
    p.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    p.add_argument("--keep-journal", action="store_true", help="leave the system journal alone")
    p.set_defaults(fn=lambda a: sys.exit(wipe.run(a.dry_run, a.yes, a.keep_journal, targets=a.targets, poweroff=a.poweroff)))

    p = sub.add_parser("disk", help="disk usage of the lab and noxy's sources")
    p.set_defaults(fn=cmd_disk)

    p = sub.add_parser("log", help="commands noxy has run")
    p.set_defaults(fn=cmd_log)

    a = ap.parse_args()
    if os.geteuid() == 0 and a.cmd not in ("setup", "wipe", "vpn"):
        sys.exit("Run noxy as your own account, not as root (only `setup`, `wipe` and `vpn` need sudo).")
    a.fn(a)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:                          # output piped into head/less and closed early
        sys.stderr.close()
    except KeyboardInterrupt:
        sys.exit(130)
