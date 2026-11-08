"""Start fresh: delete the collected logs (audit, captures, Sysmon, optionally the system journal).

Runs only as root (`sudo python3 noxy.py wipe`). There is deliberately no web button for it: a passwordless wipe
would let anything running as your user, including a lure that ran by accident, erase the evidence noxy exists to
keep. It refuses while a session is open, logs every wipe to /var/lib/noxy/wipes.log and the journal, and never
touches noxy's database (sessions are deleted from the sessions tab or `noxy.py session purge`).
"""
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

from . import sysmon, util

WIPES_LOG = Path(os.environ.get("NOXY_WIPES_LOG") or "/var/lib/noxy/wipes.log")


def _files(directory, pattern):
    d = Path(directory)
    out = []
    try:
        for f in d.iterdir():
            if re.fullmatch(pattern, f.name) and f.is_file() and not f.is_symlink():
                out.append(f)
    except OSError:
        pass
    return sorted(out)


def _size(files):
    total = 0
    for f in files:
        try:
            total += f.stat().st_size
        except OSError:
            pass
    return total


def plan():
    """What a wipe removes: [{key, label, files, size, note}]."""
    audit = _files(util.AUDIT_DIR, r"audit\.log(\.\d+)?")
    pcaps = _files(util.PCAP_DIR, r"[\w.-]+\.pcap")
    sm = sysmon.log_files()
    return [
        {"key": "audit", "label": "audit log", "files": audit, "size": _size(audit),
         "note": "auditd starts a new, empty log; the old ones are deleted"},
        {"key": "captures", "label": "captures", "files": pcaps, "size": _size(pcaps),
         "note": "the capture service is stopped for a moment and started again"},
        {"key": "sysmon", "label": "Sysmon log", "files": sm, "size": _size(sm),
         "note": "emptied in place; rotations deleted" if sm else "not set up"},
    ]


def last_wipe():
    try:
        lines = WIPES_LOG.read_text(errors="replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            return util.parse_time(line.split()[0])
        except (IndexError, ValueError):
            continue
    return None


def open_session(db_path=None):
    """Name of the open session, '' if none, None if the database can't be read."""
    p = Path(db_path or util.DATA / "noxy.db")
    if not p.exists():
        return ""
    owner = None
    try:
        owner = p.stat()
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5)
        try:
            row = con.execute("SELECT name FROM sessions WHERE ended IS NULL ORDER BY started DESC LIMIT 1").fetchone()
        finally:
            con.close()
        return row[0] if row else ""
    except sqlite3.Error:
        return None
    finally:
        # Reading as root must never leave root-owned -wal/-shm files that would lock your account out of noxy.
        if owner is not None and os.geteuid() == 0:
            for suffix in ("-wal", "-shm"):
                q = Path(str(p) + suffix)
                try:
                    if q.exists() and q.stat().st_uid != owner.st_uid:
                        os.chown(q, owner.st_uid, owner.st_gid)
                except OSError:
                    pass


LOGS = ("audit", "captures", "sysmon", "journal")
EXTRA = ("noxy", "history", "temp")
TARGETS = LOGS + EXTRA
HISTORY_FILES = (".bash_history", ".zsh_history", ".python_history", ".node_repl_history", ".lesshst", ".sqlite_history",
                 ".wget-hsts", ".viminfo", ".local/share/recently-used.xbel")
TEMP_DIRS = (Path("/tmp"), Path("/var/tmp"))
ROOT_HOME = Path("/root")
TEMP_SKIP = re.compile(r"^(\.|systemd-private-|snap-private-tmp|tracker-extract|ssh-|pulse-|vmware-root)")


def resolve(names):
    """[] -> the four log sources; 'all' -> the same; 'snapshot' -> everything. Unknown names raise ValueError."""
    names = [n.lower() for n in names] or ["all"]
    out = []
    for n in names:
        if n == "all":
            out += LOGS
        elif n == "snapshot":
            out += TARGETS
        elif n in TARGETS:
            out.append(n)
        else:
            raise ValueError(f"unknown target '{n}': choose from {', '.join(TARGETS)}, all, snapshot")
    return [t for t in TARGETS if t in out]


def _user():
    """The account that ran sudo: its home holds the history files, its uid owns its temp files."""
    import pwd
    name = os.environ.get("SUDO_USER") or ""
    try:
        pw = pwd.getpwnam(name) if name and name != "root" else None
    except KeyError:
        pw = None
    return pw


def _history_files(pw):
    homes = [Path(pw.pw_dir)] if pw else []
    homes.append(ROOT_HOME)
    return [h / f for h in homes for f in HISTORY_FILES if (h / f).is_file() and not (h / f).is_symlink()]


def _temp_entries(pw):
    if not pw:
        return []
    out = []
    for d in TEMP_DIRS:
        try:
            for e in d.iterdir():
                st = e.lstat()
                if st.st_uid == pw.pw_uid and not TEMP_SKIP.match(e.name) and (e.is_file() or e.is_dir() or e.is_symlink()):
                    import stat as _st
                    if not _st.S_ISSOCK(st.st_mode):
                        out.append(e)
        except OSError:
            pass
    return sorted(out)


def _noxy_files():
    files = [f for d in ("exports", "backups") for f in _files(util.DATA / d, r"[^/]+")]
    files += _files(util.ROOT, r"noxy-[\w.]+\.zip")
    prev = util.ROOT / ".previous-versions"
    return files, (prev if prev.is_dir() else None)


def run(dry=False, yes=False, keep_journal=False, say=print, targets=None, poweroff=False):
    if os.geteuid() != 0 and not dry:
        sys.exit("The wipe deletes root-owned logs: run it with sudo (or add --dry-run to preview).")
    try:
        chosen = resolve(targets or [])
    except ValueError as e:
        sys.exit(str(e))
    if keep_journal and "journal" in chosen:
        chosen.remove("journal")
    pw = _user()
    sizes = {i["key"]: i for i in plan()}
    total = sum(sizes[k]["size"] for k in ("audit", "captures", "sysmon") if k in chosen)
    snapshot = all(t in chosen for t in TARGETS)
    say("noxy wipe: " + ", ".join(chosen) + (" [dry run]" if dry else ""))
    for k in ("audit", "captures", "sysmon"):
        if k in chosen:
            i = sizes[k]
            say(f"  {i['label']:<12} {util.human_bytes(i['size']):>9} in {len(i['files'])} files   ({i['note']})")
    if "journal" in chosen:
        say(f"  {'journal':<12} {'':>9}    the whole system journal is emptied (it holds a copy of every Sysmon event)")
    if "noxy" in chosen:
        nf, prev = _noxy_files()
        say(f"  {'noxy':<12} {'':>9}    all sessions and notes, the command log, {len(nf)} exports, backups and release zips"
            + (", old versions kept by the updater" if prev else ""))
    if "history" in chosen:
        say(f"  {'history':<12} {'':>9}    {len(_history_files(pw))} shell and tool history files emptied (yours and root's)")
    if "temp" in chosen:
        say(f"  {'temp':<12} {'':>9}    {len(_temp_entries(pw))} of your files and folders in /tmp and /var/tmp")
    if "noxy" not in chosen:
        say("  noxy's sessions and notes are kept (add the target 'noxy', or delete them on the sessions tab).")

    name = open_session()
    if name:
        sys.exit(f"\nSession \"{util.safe_text(name, 80)}\" is open: end it first, so its evidence isn't deleted under it.")
    if name is None:
        say("\n  ! couldn't read noxy's database to check for an open session")
    if dry:
        say("\nDry run: nothing deleted.")
        return 0
    if not yes:
        try:
            if input('\nType "wipe" to go ahead: ').strip() != "wipe":
                say("Nothing deleted.")
                return 1
        except EOFError:
            sys.exit("No confirmation: add --yes to run without asking.")

    def act(cmd):
        rc, out = util.run(cmd, timeout=120)
        say(f"  $ {' '.join(cmd)}" + ("" if rc == 0 else f"\n    ! exit {rc}: {out.strip()[:300]}"))
        return rc

    def rm(f):
        try:
            if f.is_dir() and not f.is_symlink():
                import shutil
                shutil.rmtree(f)
            else:
                f.unlink()
            return True
        except FileNotFoundError:
            return True
        except OSError as e:
            say(f"    ! {f}: {e}")
            return False

    say("")
    if "noxy" in chosen:
        # the database belongs to your account: purge it as you, so no root-owned files end up in data/
        if pw:
            act(["runuser", "-u", pw.pw_name, "--", sys.executable, str(util.ROOT / "noxy.py"), "session", "purge", "--yes"])
        else:
            say("    ! not run through sudo from your account: sessions not purged (python3 noxy.py session purge)")
        nf, prev = _noxy_files()
        n = sum(rm(f) for f in nf) + (rm(prev) if prev else 0)
        say(f"  - deleted {n} noxy exports, backups, release zips and old versions")

    if "captures" in chosen:
        # the file being written is only safe to remove while the capture is stopped
        was_running = util.run(["systemctl", "is-active", "--quiet", "noxy-capture"])[0] == 0
        if was_running:
            act(["systemctl", "stop", "noxy-capture"])
        removed = sum(rm(f) for f in _files(util.PCAP_DIR, r"[\w.-]+\.pcap"))
        say(f"  - deleted {removed} capture files")
        if was_running:
            act(["systemctl", "start", "noxy-capture"])

    if "audit" in chosen:
        # ask auditd to start a new file, then delete every rotated one
        if act(["auditctl", "--signal", "rotate"]) != 0:
            act(["systemctl", "kill", "-s", "USR1", "auditd"])
        time.sleep(1.5)
        rotated = _files(util.AUDIT_DIR, r"audit\.log\.\d+")
        removed = sum(rm(f) for f in rotated)
        if not rotated:                               # rotation didn't happen: empty the live log instead
            try:
                os.truncate(util.AUDIT_DIR / "audit.log", 0)
                say("  - emptied audit.log (auditd did not rotate)")
            except OSError as e:
                say(f"    ! audit.log: {e}")
        say(f"  - deleted {removed} rotated audit logs")

    if "sysmon" in chosen:
        # rsyslog keeps the file open in append mode, so empty it in place; delete rotations
        files = sysmon.log_files()
        for f in files:
            if f.name == sysmon.LOG.name:
                try:
                    os.truncate(f, 0)
                except OSError as e:
                    say(f"    ! {f}: {e}")
            else:
                rm(f)
        say(f"  - emptied the Sysmon log ({len(files)} files)" if files else "  - no Sysmon log")

    if "history" in chosen:
        hf = _history_files(pw)
        for f in hf:
            try:
                os.truncate(f, 0)
            except OSError as e:
                say(f"    ! {f}: {e}")
        say(f"  - emptied {len(hf)} history files")

    if "temp" in chosen:
        te = _temp_entries(pw)
        n = sum(rm(e) for e in te)
        say(f"  - deleted {n} of your entries in /tmp and /var/tmp")

    if "journal" in chosen:
        act(["journalctl", "--rotate"])
        act(["journalctl", "--vacuum-time=1s"])

    stamp = util.iso(util.now_ts())
    who = pw.pw_name if pw else "root"
    line = f"{stamp} wipe by {who}: {', '.join(chosen)}; {util.human_bytes(total)} of logs deleted"
    try:
        WIPES_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(WIPES_LOG, "a") as fh:
            fh.write(line + "\n")
        try:
            import grp
            os.chown(WIPES_LOG, 0, grp.getgrnam("noxy").gr_gid)
            os.chmod(WIPES_LOG, 0o640)
        except (KeyError, OSError):
            pass
    except OSError as e:
        say(f"    ! {WIPES_LOG}: {e}")
    if "journal" not in chosen:
        util.run(["logger", "-t", "noxy", line])
    say(f"\nDone: {line}.")
    if snapshot:
        say("\nBefore the snapshot, by hand:\n"
            "  - Firefox: close it, or clear its history (Ctrl+Shift+Del) if you visited live pages\n"
            "  - ~/Downloads and ~/Documents: remove samples and anything from a case\n"
            "  - VPN: `vpn off` if the snapshot should start online (with the kill switch on it starts offline)\n"
            "  - open terminals: close them with `history -c; exit`, or bash writes its history again on exit\n"
            "  - host: put the clipboard back to the hardened settings (host_harden.py vmx ... --apply)")
    if poweroff:
        say("\nShutting down now: take the snapshot with the VM powered off.")
        util.run(["systemctl", "poweroff"])
    return 0
