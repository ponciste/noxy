"""Lab status. Reads /proc, /sys and config files only: no subprocesses, so polling adds no audit noise."""
import grp
import os
import re
import shutil
from pathlib import Path

from . import sysmon, util

VPN_IFACE = re.compile(r"^(wg|proton|pvpn|tun|tap|ppp|nordlynx|mullvad|ipsec)", re.I)


def _procs():
    out = []
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            comm = (d / "comm").read_text().strip()
            cmd = (d / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace").strip()
        except OSError:
            continue
        out.append((int(d.name), comm, cmd))
    return out


def capture_running():
    return any("tcpdump" in c and str(util.PCAP_DIR) in c for _, _, c in _procs())


def egress():
    """{'mode': 'offline'|'home'|'vpn', 'iface': ..., 'label': ...} from the kernel routing tables."""
    defaults = []
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) >= 8 and f[1] == "00000000" and f[7] == "00000000":
                defaults.append((int(f[6]) if f[6].isdigit() else 0, f[0]))
    except OSError:
        pass
    try:
        for line in Path("/proc/net/ipv6_route").read_text().splitlines():
            f = line.split()
            if len(f) >= 10 and f[0] == "0" * 32 and f[1] == "00" and f[9] != "lo":
                defaults.append((int(f[5], 16), f[9]))
    except OSError:
        pass
    # wg-quick routes everything through its own table (not the main one), so a tunnel shows as an interface,
    # not as a default route. The kill switch (ufw dropping outgoing) means "offline" when no tunnel is up.
    from . import vpn as _vpn
    tunnels = []
    try:
        for d in sorted(_vpn.SYS_NET.iterdir()):
            if VPN_IFACE.match(d.name) and (d / "operstate").exists() and (d / "operstate").read_text().strip() != "down":
                tunnels.append(d.name)
    except OSError:
        pass
    tunnels += [i for _, i in defaults if VPN_IFACE.match(i) and i not in tunnels]
    ks = _vpn.killswitch()
    if tunnels:
        return {"mode": "vpn", "iface": tunnels[0], "label": f"vpn ({tunnels[0]})", "killswitch": ks}
    if ks:
        return {"mode": "offline", "iface": None, "label": "offline (kill switch on, VPN down)", "killswitch": True}
    if not defaults:
        return {"mode": "offline", "iface": None, "label": "offline", "killswitch": False}
    iface = sorted(defaults)[0][1]
    return {"mode": "home", "iface": iface, "label": f"home IP ({iface})", "killswitch": False}


def ether_ifaces():
    out = []
    try:
        for d in Path("/sys/class/net").iterdir():
            if d.name == "lo" or not (d / "device").exists():
                continue
            state = (d / "operstate").read_text().strip() if (d / "operstate").exists() else "?"
            out.append({"name": d.name, "state": state})
    except OSError:
        pass
    return sorted(out, key=lambda x: x["name"])


def _check(cid, label, state, detail="", hint=""):
    return {"id": cid, "label": label, "state": state, "detail": detail, "hint": hint}


RESOLVERS = {
    "9.9.9.10": ("Quad9 unfiltered", "ok"), "149.112.112.10": ("Quad9 unfiltered", "ok"),
    "2620:fe::10": ("Quad9 unfiltered", "ok"), "2620:fe::fe:10": ("Quad9 unfiltered", "ok"),
    "9.9.9.9": ("Quad9 filtering", "warn"), "149.112.112.112": ("Quad9 filtering", "warn"),
    "9.9.9.11": ("Quad9 filtering", "warn"), "149.112.112.11": ("Quad9 filtering", "warn"),
    "1.1.1.1": ("Cloudflare", "ok"), "1.0.0.1": ("Cloudflare", "ok"),
    "1.1.1.2": ("Cloudflare filtering", "warn"), "1.0.0.2": ("Cloudflare filtering", "warn"),
    "1.1.1.3": ("Cloudflare filtering", "warn"), "10.2.0.1": ("Proton VPN DNS", "ok"),
}


def resolvers():
    """Upstream DNS servers systemd-resolved uses (world-readable file, no subprocess)."""
    text = ""
    for f in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            text = Path(f).read_text()
            break
        except OSError:
            continue
    return [m for m in re.findall(r"(?m)^\s*nameserver\s+(\S+)", text) if m not in ("127.0.0.53", "127.0.0.54")]


def dns_check():
    servers = resolvers()
    if not servers:
        return _check("dns", "DNS resolver", "info", "none configured (offline?)")
    names, worst = [], "ok"
    for ip in servers[:4]:
        name, state = RESOLVERS.get(ip, (None, "info"))
        if name is None and re.match(r"^192\.168\.\d+\.2$", ip):
            name, state = "VMware DNS proxy (blocked by the host rule)", "warn"
        names.append(f"{name} ({ip})" if name else ip)
        if state == "warn":
            worst = "warn"
    hint = ""
    if worst == "warn":
        hint = ("A filtering resolver or VMware's proxy is in use: known-bad domains may look dead. "
                "sudo python3 hardening/vm_harden.py system --only network")
    return _check("dns", "DNS resolver", worst, ", ".join(names), hint)


def rules_active(alog):
    """True if recent audit records carry noxy's keys (exec and net), False if not, None if unknown.

    Reads the tail of audit.log instead of /etc/audit/rules.d, which only root can read."""
    try:
        with open(alog, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 512 * 1024))
            tail = f.read()
    except OSError:
        return None
    if not tail:
        return None
    return b'key="exec"' in tail or b"key=exec" in tail


def _file_text(path):
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def checks(home=None):
    """Every check runs on its own: one that fails (permissions, missing tools) shows as a warning, never an error."""
    home = Path(home or Path.home())
    procs = _procs()
    res = []
    eg = egress()

    def guard(cid, label, fn):
        try:
            out = fn()
            if out:
                res.append(out)
        except Exception as e:                       # noqa: BLE001 - a status page must always render
            res.append(_check(cid, label, "warn", f"could not check ({type(e).__name__})", str(e)[:200]))

    guard("egress", "egress", lambda: _check(
        "egress", "egress", {"offline": "ok", "vpn": "ok", "home": "info"}[eg["mode"]], eg["label"],
        "" if eg["mode"] != "home" else "Online from your home IP. Turn Proton on (sudo python3 noxy.py vpn on) before "
        "visiting attacker infrastructure, or disconnect the NAT adapter for offline work."))

    def vpn_check():
        from . import vpn as _vpn
        s = _vpn.state()
        if not s["configs"]:
            return _check("vpn", "VPN (Proton)", "info", "not set up",
                          "Download WireGuard configs from Proton, then: sudo python3 noxy.py vpn install ~/path/*.conf")
        if s["mode"] == "on" and not s["killswitch"]:
            return _check("vpn", "VPN (Proton)", "warn", s["text"], "sudo python3 noxy.py vpn on   (applies the kill switch again)")
        return _check("vpn", "VPN (Proton)", "ok" if s["mode"] != "off" else "info", s["text"],
                      "" if s["mode"] != "off" else f"{len(s['configs'])} configs: " + ", ".join(c["name"] for c in s["configs"]))
    guard("vpn", "VPN (Proton)", vpn_check)

    def group():
        try:
            gid = grp.getgrnam("noxy").gr_gid
        except KeyError:
            return _check("group", "noxy group", "fail", "missing", "Run `sudo python3 noxy.py setup lab`.")
        member = gid in os.getgroups()
        return _check("group", "noxy group", "ok" if member else "fail", "member" if member else "not active for this login",
                      "" if member else "Reboot (or log out completely) after `sudo python3 noxy.py setup lab`.")
    guard("group", "noxy group", group)

    auditd = any(c == "auditd" for _, c, _ in procs)
    guard("auditd", "auditd", lambda: _check("auditd", "auditd", "ok" if auditd else "fail",
                                              "running" if auditd else "not running",
                                              "" if auditd else "sudo systemctl enable --now auditd"))
    alog = util.AUDIT_DIR / "audit.log"
    readable = os.access(alog, os.R_OK)
    guard("audit-read", "audit log readable", lambda: _check(
        "audit-read", "audit log readable", "ok" if readable else "fail", str(alog),
        "" if readable else "sudo python3 noxy.py setup lab, then reboot"))

    def rules():
        active = rules_active(alog) if readable else None
        if active:
            return _check("audit-rules", "noxy audit rules", "ok", "active (exec records in the log)")
        if active is False:
            return _check("audit-rules", "noxy audit rules", "warn", "no exec records in the recent log",
                          "sudo augenrules --load, then `sudo auditctl -l` should list -k exec and -k net")
        return _check("audit-rules", "noxy audit rules", "warn", "unknown (audit log not readable)",
                      "fix 'audit log readable' first")
    guard("audit-rules", "noxy audit rules", rules)

    def fresh():
        if not readable:
            return None
        age = util.now_ts() - alog.stat().st_mtime
        return _check("audit-fresh", "audit log fresh", "ok" if age < 300 else "warn", f"last write {int(age)}s ago",
                      "" if age < 300 else "auditd may be stuck or rules missing")
    guard("audit-fresh", "audit log fresh", fresh)

    cap = any("tcpdump" in c and str(util.PCAP_DIR) in c for _, _, c in procs)
    guard("capture", "capture", lambda: _check("capture", "capture", "ok" if cap else "fail",
                                                "recording" if cap else "not running",
                                                "" if cap else "sudo systemctl enable --now noxy-capture"))

    def storage():
        files = sorted(util.PCAP_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in files)
        free = shutil.disk_usage(util.PCAP_DIR).free
        return _check("capture-disk", "capture storage", "ok" if free > 2 * 1024 ** 3 else "warn",
                      f"{len(files)} files, {util.human_bytes(total)}; {util.human_bytes(free)} free",
                      "" if free > 2 * 1024 ** 3 else "Free space below 2 GB: lower capture retention.")
    guard("capture-disk", "capture storage", storage)

    def utc():
        tz = os.path.realpath("/etc/localtime")
        ok = tz.endswith(("/UTC", "/Etc/UTC", "/UCT", "/Zulu", "Universal"))
        return _check("utc", "time zone UTC", "ok" if ok else "fail", tz.rsplit("zoneinfo/", 1)[-1] or "?",
                      "" if ok else "sudo timedatectl set-timezone Etc/UTC")
    guard("utc", "time zone UTC", utc)

    def firewall():
        on = bool(re.search(r"(?m)^ENABLED=yes", _file_text("/etc/ufw/ufw.conf")))
        return _check("firewall", "VM firewall", "ok" if on else "warn", "ufw enabled" if on else "ufw off",
                      "" if on else "sudo python3 hardening/vm_harden.py system --only firewall")
    guard("firewall", "VM firewall", firewall)

    def vscode():
        vs = util.load_jsonc(home / ".config/Code/User/settings.json") or {}
        ok = vs.get("task.allowAutomaticTasks") == "off" and vs.get("typescript.disableAutomaticTypeAcquisition") is True
        return _check("vscode", "VS Code safe settings", "ok" if ok else "warn", "on" if ok else "missing",
                      "" if ok else "python3 hardening/vm_harden.py user --only editors")
    guard("vscode", "VS Code safe settings", vscode)

    def npm():
        ok = "ignore-scripts=true" in _file_text(home / ".npmrc")
        return _check("npm", "npm ignore-scripts", "ok" if ok else "warn", "on" if ok else "off",
                      "" if ok else "python3 hardening/vm_harden.py user --only npm")
    guard("npm", "npm ignore-scripts", npm)

    def git():
        ok = bool(re.search(r"(?mi)^\s*hooksPath\s*=\s*/dev/null", _file_text(home / ".gitconfig")))
        return _check("git", "git hooks off", "ok" if ok else "warn", "hooksPath=/dev/null" if ok else "hooks enabled",
                      "" if ok else "python3 hardening/vm_harden.py user --only git")
    guard("git", "git hooks off", git)

    def files():
        run = sysmon.running(procs)
        installed = run or any(os.path.exists(p) for p in ("/usr/bin/sysmon", "/opt/sysmon/sysmon"))
        if not installed:
            return _check("sysmon", "file creation (Sysmon)", "info", "not installed",
                          "Optional, watches file creation anywhere: sudo python3 noxy.py setup sysmon")
        if not run:
            return _check("sysmon", "file creation (Sysmon)", "warn", "installed, not running",
                          "sudo systemctl enable --now sysmon")
        if not os.access(sysmon.LOG, os.R_OK):
            return _check("sysmon", "file creation (Sysmon)", "warn", f"running, {sysmon.LOG} not readable",
                          "sudo python3 noxy.py setup sysmon, then reboot")
        return _check("sysmon", "file creation (Sysmon)", "ok", "running, log readable")
    guard("sysmon", "file creation (Sysmon)", files)

    guard("dns", "DNS resolver", dns_check)
    guard("nics", "network adapters", lambda: _check(
        "nics", "network adapters", "info", ", ".join(f"{n['name']} {n['state']}" for n in ether_ifaces()) or "none"))
    return {"checks": res, "egress": eg, "capture": cap, "auditd": auditd,
            "summary": {s: sum(1 for c in res if c["state"] == s) for s in ("ok", "warn", "fail", "info")}}
