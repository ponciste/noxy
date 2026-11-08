"""Proton VPN over plain WireGuard, with a kill switch. Changes run as root: `sudo python3 noxy.py vpn ...`.

  vpn install FILE...   validate Proton WireGuard configs, install them as /etc/wireguard/proton-<cc>.conf (root, 0600),
                        shred the originals
  vpn on [CC]           kill switch first (ufw: outgoing denied except the tunnel), then the tunnel; checks the handshake
  vpn off               tunnel down, kill switch off (ufw outgoing allowed again)
  vpn status            readable by your user too

No web button on purpose: switching the VPN off without a password would let anything running as your user expose
your home IP. Configs are treated as untrusted input: only the WireGuard keys Proton uses are accepted, so a file
with PostUp/PreDown (commands wg-quick would run as root) is refused.

After a reboot the tunnel is down but the kill switch stays (ufw keeps its default), so the VM is offline until you
choose `vpn on` or `vpn off`: it never falls back to your home IP by itself.
"""
import ipaddress
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

from . import util

WG_DIR = Path(os.environ.get("NOXY_WG_DIR") or "/etc/wireguard")
INDEX = Path(os.environ.get("NOXY_VPN_INDEX") or "/etc/noxy/vpn.json")   # names, countries, endpoints; no keys
UFW_DEFAULT = Path("/etc/default/ufw")
UFW_CONF = Path("/etc/ufw/ufw.conf")
SYS_NET = Path("/sys/class/net")
PREFIX = "proton-"
COMMENT = "noxy-vpn"
ALLOWED = {
    "interface": {"privatekey", "address", "dns", "mtu"},
    "peer": {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"},
}
KEY = re.compile(r"^[A-Za-z0-9+/]{42,43}=$")


class VpnError(Exception):
    pass


# ------------------------------------------------------------------ configs

def parse_conf(text):
    """Validate a Proton WireGuard config. Returns its public facts; raises VpnError with the reason."""
    if len(text) > 8192:
        raise VpnError("too large for a WireGuard config")
    section, seen, facts = None, {"interface": {}, "peer": {}}, {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        m = re.fullmatch(r"\[(\w+)\]", line)
        if m:
            section = m.group(1).lower()
            if section not in seen:
                raise VpnError(f"line {n}: unexpected section [{m.group(1)}]")
            if seen[section]:
                raise VpnError(f"line {n}: more than one [{m.group(1)}] section")
            seen[section]["_"] = True
            continue
        k, sep, v = line.partition("=")
        k, v = k.strip().lower(), v.strip()
        if not sep or section is None:
            raise VpnError(f"line {n}: not a WireGuard setting")
        if k not in ALLOWED[section]:
            raise VpnError(f"line {n}: '{k}' is not accepted (only the settings Proton's configs use; "
                           "PostUp, PreDown and similar would run commands as root)")
        seen[section][k] = v
    i, p = seen["interface"], seen["peer"]
    for sec, key in (("interface", "privatekey"), ("peer", "publickey")):
        if not KEY.match(seen[sec].get(key, "")):
            raise VpnError(f"[{sec.title()}] {key}: missing or not a WireGuard key")
    if not i.get("address"):
        raise VpnError("[Interface] Address missing")
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", p.get("endpoint", ""))
    if not m:
        raise VpnError("[Peer] Endpoint must be an IPv4 address and port (the kill switch allows exactly that)")
    ip = ipaddress.ip_address(m.group(1))
    if not ip.is_global:
        raise VpnError(f"[Peer] Endpoint {ip} is not a public address")
    allowed = [a.strip() for a in p.get("allowedips", "").split(",")]
    if "0.0.0.0/0" not in allowed:
        raise VpnError("[Peer] AllowedIPs must include 0.0.0.0/0 (all traffic through the tunnel)")
    facts.update(endpoint=str(ip), port=int(m.group(2)), dns=[d.strip() for d in i.get("dns", "").split(",") if d.strip()],
                 ipv6=any(":" in a for a in i["address"].split(",")))
    return facts


def strip_ipv6(text):
    """For VMs with IPv6 disabled: wg-quick fails to add an IPv6 address. Keep IPv4 only (the kill switch still
    blocks IPv6, since ufw's default deny applies to both)."""
    out = []
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        key = k.strip().lower()
        if sep and key in ("address", "allowedips", "dns"):
            keep = [x.strip() for x in v.split(",") if ":" not in x]
            if not keep:
                continue
            line = f"{k.rstrip()} = {', '.join(keep)}"
        out.append(line)
    return "\n".join(out) + "\n"


def country_of(path):
    """noxy-ch.conf, proton-ch.conf, ch.conf, wg-CH-12.conf -> 'ch'."""
    stem = Path(path).stem.lower()
    parts = [x for x in re.split(r"[-_. ]+", stem) if x and x not in ("noxy", "proton", "protonvpn", "wg", "free", "conf")]
    letters = [x for x in parts if re.fullmatch(r"[a-z]{2}", x)]
    name = letters[0] if letters else (parts[0] if parts else "")
    if not re.fullmatch(r"[a-z0-9]{2,8}", name):
        raise VpnError(f"{Path(path).name}: can't tell the country from the name; rename it like noxy-ch.conf")
    return name


def configs():
    try:
        data = json.loads(INDEX.read_text())
        return [c for c in data.get("configs", []) if re.fullmatch(r"[a-z0-9]{2,8}", c.get("name", ""))]
    except (OSError, ValueError):
        return []


def ipv6_disabled():
    try:
        return Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").read_text().strip() == "1"
    except OSError:
        return False


# ------------------------------------------------------------------ state (readable by your user)

def active():
    try:
        return sorted(d.name for d in SYS_NET.iterdir() if d.name.startswith(PREFIX))
    except OSError:
        return []


def _kv(path):
    out = {}
    try:
        for line in path.read_text().splitlines():
            k, sep, v = line.partition("=")
            if sep and not k.strip().startswith("#"):
                out[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return out


def killswitch():
    """True when ufw is enabled and drops outgoing traffic by default."""
    return _kv(UFW_CONF).get("ENABLED", "").lower() == "yes" and _kv(UFW_DEFAULT).get("DEFAULT_OUTPUT_POLICY", "") in ("DROP", "REJECT")


def state():
    act = active()
    ks = killswitch()
    cfgs = configs()
    if act:
        mode, text = "on", f"on through {act[0]}" + ("" if ks else " (kill switch OFF: traffic can leave outside the tunnel)")
    elif ks:
        mode, text = "blocked", "tunnel down, kill switch on: the VM is offline"
    else:
        mode, text = "off", "off: traffic leaves from your home IP"
    return {"mode": mode, "text": text, "active": act, "killswitch": ks, "configs": cfgs,
            "command": f"sudo python3 {_tilde(util.ROOT / 'noxy.py')} vpn"}


def _tilde(p):
    home, p = os.path.expanduser("~"), str(p)
    return "~" + p[len(home):] if home not in ("", "/") and p.startswith(home + "/") else p


# ------------------------------------------------------------------ actions (root)

def _need_root():
    if os.geteuid() != 0:
        sys.exit("This changes the firewall and network: run it with sudo.")


def _run(cmd, say, ok=(0,), timeout=60):
    rc, out = util.run(cmd, timeout=timeout)
    say(f"  $ {' '.join(cmd)}" + ("" if rc in ok else f"\n    ! exit {rc}: {out.strip()[:300]}"))
    return rc, out


def install(paths, keep=False, say=print):
    _need_root()
    if not shutil.which("wg-quick"):
        sys.exit("wg-quick is missing: sudo apt install -y wireguard-tools")
    index = {c["name"]: c for c in configs()}
    plan = []
    for p in paths:
        p = Path(p)
        try:
            if p.is_symlink() or not p.is_file():
                raise VpnError("not a regular file")
            text = p.read_text(errors="strict")
            facts = parse_conf(text)
            name = country_of(p)
        except (VpnError, OSError, UnicodeDecodeError) as e:
            sys.exit(f"{p.name}: {e}. Nothing installed.")
        if name in [x[1] for x in plan]:
            sys.exit(f"{p.name}: two files for '{name}'. Nothing installed.")
        plan.append((p, name, text, facts))
    no6 = ipv6_disabled()
    WG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    for p, name, text, facts in plan:
        if no6 and facts["ipv6"]:
            text = strip_ipv6(text)
        dest = WG_DIR / f"{PREFIX}{name}.conf"
        tmp = dest.with_suffix(".tmp")
        old = os.umask(0o077)
        try:
            tmp.write_text(text)
            os.chown(tmp, 0, 0)
            os.chmod(tmp, 0o600)
            os.replace(tmp, dest)
        finally:
            os.umask(old)
        index[name] = {"name": name, "iface": f"{PREFIX}{name}", "endpoint": facts["endpoint"], "port": facts["port"],
                       "dns": facts["dns"], "installed": util.iso(util.now_ts())}
        say(f"  + {dest}  ({name}, endpoint {facts['endpoint']}:{facts['port']})" + ("  IPv6 removed: disabled on this VM" if no6 and facts["ipv6"] else ""))
    INDEX.parent.mkdir(parents=True, exist_ok=True)
    INDEX.write_text(json.dumps({"configs": sorted(index.values(), key=lambda c: c["installed"])}, indent=1))
    os.chmod(INDEX, 0o644)
    if not shutil.which("resolvconf") and shutil.which("resolvectl"):
        # wg-quick sets the tunnel's DNS through `resolvconf`; systemd's resolvectl speaks that interface by this name
        link = Path("/usr/local/bin/resolvconf")
        if not link.exists():
            link.symlink_to(shutil.which("resolvectl"))
            say(f"  + {link} -> resolvectl (wg-quick needs it for the tunnel's DNS)")
    if not keep:
        for p, *_ in plan:
            rc, _ = util.run(["shred", "-u", str(p)])
            if rc != 0:
                p.unlink(missing_ok=True)
            say(f"  - shredded {p}")
    say(f"\nInstalled: {', '.join(n for _, n, _, _ in plan)}. Turn it on with: sudo python3 noxy.py vpn on {plan[0][1]}")


def _ufw_enabled():
    return _kv(UFW_CONF).get("ENABLED", "").lower() == "yes"


def _delete_rules(say):
    """Remove every ufw rule noxy added (they carry the comment noxy-vpn), highest number first."""
    for _ in range(20):
        rc, out = util.run(["ufw", "status", "numbered"])
        nums = [int(m.group(1)) for m in re.finditer(r"^\[\s*(\d+)\].*" + COMMENT, out, re.M)]
        if not nums:
            return
        _run(["ufw", "--force", "delete", str(max(nums))], say)


def _first_rule(rule, say):
    """Put a rule above the VM firewall's 'deny private ranges' rules: Proton's DNS (10.2.0.1) is a private address
    reached through the tunnel. `ufw prepend` does exactly that; `insert 1` is the fallback for older ufw."""
    for verb in (["prepend"], ["insert", "1"], []):
        rc, out = util.run(["ufw", *verb, *rule])
        if rc == 0:
            say(f"  $ ufw {' '.join(verb + rule)}")
            return True
    say(f"    ! ufw refused: {' '.join(rule)}: {out.strip()[:200]}")
    return False


def on(name=None, say=print, wait=15):
    _need_root()
    cfgs = configs()
    if not cfgs:
        sys.exit("No VPN configs installed: sudo python3 noxy.py vpn install ~/path/to/*.conf")
    c = next((x for x in cfgs if x["name"] == name), None) if name else cfgs[0]
    if not c:
        sys.exit(f"No config named '{name}'. Installed: {', '.join(x['name'] for x in cfgs)}")
    if not _ufw_enabled():
        sys.exit("The VM firewall (ufw) is off, so there is no kill switch: sudo python3 hardening/vm_harden.py system --only firewall")
    say(f"VPN on through {c['iface']} ({c['endpoint']}:{c['port']})")
    for iface in active():
        _run(["wg-quick", "down", iface], say)
    _delete_rules(say)
    # kill switch first: from here nothing leaves the VM except the tunnel and its endpoint
    _first_rule(["allow", "out", "to", c["endpoint"], "port", str(c["port"]), "proto", "udp", "comment", COMMENT], say)
    _first_rule(["allow", "out", "on", c["iface"], "comment", COMMENT], say)
    _run(["ufw", "default", "deny", "outgoing"], say)
    rc, out = _run(["wg-quick", "up", c["iface"]], say)
    if rc != 0:
        if "resolvconf" in out:
            say("    wg-quick needs resolvconf: sudo ln -s /usr/bin/resolvectl /usr/local/bin/resolvconf")
        sys.exit("The tunnel did not come up. The kill switch stays on, so the VM is offline. "
                 "Try another config, or turn everything off with: sudo python3 noxy.py vpn off")
    for _ in range(wait):
        rc, out = util.run(["wg", "show", c["iface"], "latest-handshakes"])
        parts = out.split()
        if rc == 0 and len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) > 0:
            say(f"\nOn: handshake with {c['endpoint']} done. Traffic leaves through Proton ({c['name']}); "
                "noxy's header shows the VPN IP within a minute.")
            return 0
        time.sleep(1)
    say(f"\n! No handshake with {c['endpoint']} after {wait} seconds. The kill switch stays on (the VM is offline). "
        "The server may be busy: try another one (sudo python3 noxy.py vpn on <name>) or `vpn off`.")
    return 1


def off(say=print):
    _need_root()
    say("VPN off")
    for iface in active():
        _run(["wg-quick", "down", iface], say)
    _delete_rules(say)
    _run(["ufw", "default", "allow", "outgoing"], say)
    say("\nOff: traffic leaves from your home IP again (private ranges stay blocked by the VM firewall).")
    return 0


def status_text(say=print):
    s = state()
    say(f"VPN: {s['text']}")
    say(f"kill switch: {'on' if s['killswitch'] else 'off'}")
    if s["configs"]:
        for c in s["configs"]:
            mark = "*" if c["iface"] in s["active"] else " "
            say(f"  {mark} {c['name']:<6} {c['endpoint']}:{c['port']}")
    else:
        say("no configs installed: sudo python3 noxy.py vpn install ~/path/to/*.conf")
    return 0
