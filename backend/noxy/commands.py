"""Terminal equivalents ("do it yourself") for what noxy shows.

noxy itself reads /proc, the raw audit log and the captures in Python, so it runs almost no commands. These recipes
are the standard Linux tools that reproduce each panel, with every part of the command explained, to copy into the
REMnux terminal. Placeholders are filled from the session (start time, capture files) when one is given.

Safety labels:  read-only | sudo, read-only | changes the system | parses hostile data
"""
import datetime as dt
import shlex

from . import sysmon, util

RO, SUDO_RO, CHANGES, HOSTILE = "read-only", "sudo, read-only", "changes the system", "parses hostile data"


def _ts(ts):
    """ausearch time format (MM/DD/YYYY HH:MM:SS in the C/en_US locale; the VM clock is UTC)."""
    return dt.datetime.fromtimestamp(ts, util.UTC).strftime("%m/%d/%Y %H:%M:%S") if ts else "recent"


def _find_ts(ts):
    return dt.datetime.fromtimestamp(ts, util.UTC).strftime("%Y-%m-%d %H:%M:%S") if ts else "-1 hour"


def r(title, cmd, parts, safety=RO, note=""):
    return {"title": title, "cmd": cmd, "parts": parts, "safety": safety, "note": note}


def context(session=None, pcap_files=None):
    start = session["started"] if session else None
    end = session["ended"] if session else None
    files = [str(util.PCAP_DIR / f) for f in (pcap_files or [])]
    sid = session["id"] if session else "N"
    merged = f"~/noxy-session-{sid}.pcap"
    if files:
        merge = "mergecap -w " + merged + " " + " ".join(shlex.quote(f) for f in files[:40])
    else:
        merge = f"mergecap -w {merged} {util.PCAP_DIR}/lab-*.pcap"
    return {"start": _ts(start), "end": _ts(end) if end else "now", "find_start": _find_ts(start), "merged": merged,
            "merge": merge, "pcap_dir": str(util.PCAP_DIR), "audit": str(util.AUDIT_DIR), "sid": sid,
            "sysmon": str(sysmon.LOG), "sysmon_start": _find_ts(start) if start else "2026-01-01 00:00:00"}


def topics(c):
    ts_parts = [["-ts / -te", "start and end time: MM/DD/YYYY HH:MM:SS (VM clock is UTC; 'recent' = last 10 minutes)"]]
    tshark_note = ("tshark uses Wireshark's dissectors on attacker-controlled packets: run it as your user, never "
                   "with sudo. noxy uses its own memory-safe reader instead.")
    return {
        "status": [
            r("Is auditd running?", "systemctl is-active auditd",
              [["systemctl", "talks to systemd, the service manager"], ["is-active", "prints active or inactive"],
               ["auditd", "the audit daemon that writes /var/log/audit/audit.log"]]),
            r("Which audit rules are loaded?", "sudo auditctl -l",
              [["auditctl", "configures the kernel audit system"], ["-l", "list the loaded rules (noxy's have -k exec, net, persist, editor)"]],
              SUDO_RO),
            r("Is the capture running?", "systemctl status noxy-capture --no-pager",
              [["status", "state, start time and last log lines"], ["noxy-capture", "noxy's tcpdump service"],
               ["--no-pager", "print instead of opening less"]]),
            r("Newest capture files", f"ls -lht {c['pcap_dir']} | head",
              [["ls -l", "long listing"], ["-h", "human sizes"], ["-t", "newest first"], ["| head", "first 10 lines only"]]),
            r("Time zone", "timedatectl",
              [["timedatectl", "shows local time, UTC and the time zone (must be Etc/UTC)"]]),
            r("VM firewall rules", "sudo ufw status verbose",
              [["ufw", "uncomplicated firewall"], ["status verbose", "defaults and every rule"]], SUDO_RO),
            r("DNS servers in use", "resolvectl dns",
              [["resolvectl", "talks to systemd-resolved"], ["dns", "DNS servers in use (expect Quad9 unfiltered 9.9.9.10, or Proton 10.2.0.1 with the VPN on)"]]),
            r("Adapters and routes", "ip -br addr && ip route",
              [["ip -br addr", "one line per adapter with its address"], ["ip route", "the routing table: 'default via' is how traffic leaves"]]),
            r("Public IP (what noxy asks ipify)", "curl -s https://api.ipify.org; echo",
              [["curl", "HTTP client"], ["-s", "silent: no progress bar"], ["https://api.ipify.org", "answers with your public address"],
               ["; echo", "adds a newline after the answer"]], "touches the network",
              "Only when online. Through Proton, it shows the VPN address."),
            r("My groups", "id",
              [["id", "your user, groups and IDs (noxy must be listed for log access)"]]),
        ],
        "exec": [
            r("Every execution since the session start", f"sudo ausearch -k exec -ts {c['start']} -i | less",
              [["ausearch", "searches the audit log"], ["-k exec", "only records with noxy's exec key"], *ts_parts,
               ["-i", "interpret: numbers become names (uid -> user, syscall 59 -> execve)"], ["| less", "page through it (q quits, / searches)"]],
              SUDO_RO),
            r("Executions as one line each", f"sudo ausearch -k exec -ts {c['start']} --format text",
              [["--format text", "one readable sentence per event (who ran what, where)"]], SUDO_RO),
            r("Summary: which programs ran", f"sudo aureport -x -ts {c['start']} --summary -i",
              [["aureport", "summary reports from the audit log"], ["-x", "executables"], ["--summary", "counts per program"]],
              SUDO_RO),
            r("Search one command line", f"sudo ausearch -k exec -ts {c['start']} -i | grep -i 'npm install'",
              [["grep -i", "case-insensitive text filter (replace the text)"]], SUDO_RO),
            r("Process tree right now", "ps -ef --forest | less -S",
              [["ps -ef", "every process, full format"], ["--forest", "draw parent and child processes as a tree"],
               ["less -S", "don't wrap long lines (arrows scroll sideways)"]]),
            r("Process tree with arguments", "pstree -alp | less -S",
              [["pstree", "tree of processes"], ["-a", "show arguments"], ["-l", "don't cut long lines"], ["-p", "show PIDs"]]),
        ],
        "connections": [
            r("Outbound connections since the session start", f"sudo ausearch -k net -ts {c['start']} -i | less",
              [["-k net", "noxy's connect() rule"], ["-i", "decodes saddr into address and port"]], SUDO_RO),
            r("Open connections right now", "ss -tunap",
              [["ss", "socket statistics"], ["-t / -u", "TCP and UDP"], ["-n", "numbers, no name lookups"],
               ["-a", "listening and established"], ["-p", "owning process (yours; sudo shows all)"]]),
        ],
        "persistence": [
            r("Writes to persistence locations", f"sudo ausearch -k persist -ts {c['start']} -i | less",
              [["-k persist", "autostart, systemd units, cron, rc files, sudoers.d, ~/.ssh"]], SUDO_RO),
            r("VS Code settings changes", f"sudo ausearch -k editor -ts {c['start']} -i",
              [["-k editor", "writes under ~/.config/Code/User"]], SUDO_RO),
            r("Autostart and user services", "ls -la ~/.config/autostart ~/.config/systemd/user; systemctl --user list-unit-files --state=enabled",
              [["ls -la", "every file with times and permissions"], ["list-unit-files --state=enabled", "services that start by themselves"]]),
            r("Cron jobs", "crontab -l; ls -la /etc/cron.d",
              [["crontab -l", "your scheduled jobs (none expected)"], ["/etc/cron.d", "system-wide scheduled jobs"]]),
        ],
        "files": [
            r("Is Sysmon running?", "systemctl status sysmon --no-pager",
              [["sysmon", "Sysmon for Linux, the Microsoft service that writes file-creation events"],
               ["status", "state, start time and last log lines"]]),
            r("Files created since the session start",
              f"awk -v s='{c['sysmon_start']}' 'match($0, /UtcTime\">[^<]*/) && substr($0, RSTART+9, 19) >= s' {c['sysmon']} "
              "| grep -o 'Image\">[^<]*\\|TargetFilename\">[^<]*' | paste - - | sed 's/[A-Za-z]*\">//g' | less -S",
              [["awk -v s=...", "keep lines whose UtcTime is at or after the session start (UTC)"],
               ["match(...UtcTime...)", "finds the event time inside Sysmon's XML"],
               ["grep -o 'Image...\\|TargetFilename...'", "print only the process and the file it created"],
               ["paste - -", "join each process with its file on one line"], ["sed", "strip the XML field names"],
               ["less -S", "page through without wrapping"]],
              note="Each line: the program that created the file, then the file."),
            r("Files created in temp folders", f"grep -o 'TargetFilename\">/\\(tmp\\|var/tmp\\|dev/shm\\)/[^<]*' {c['sysmon']} | cut -d'>' -f2 | sort | uniq -c | sort -rn | head -50",
              [["grep -o", "print only the matching part: file names under /tmp, /var/tmp, /dev/shm"],
               ["cut -d'>' -f2", "drop the XML field name"], ["sort | uniq -c | sort -rn", "count each name, most frequent first"]]),
            r("Who created one file", f"grep -F 'TargetFilename\">/tmp/example' {c['sysmon']} | grep -o 'UtcTime\">[^<]*\\|Image\">[^<]*\\|ProcessId\">[^<]*'",
              [["grep -F", "fixed text, no pattern characters (replace /tmp/example with the file)"],
               ["UtcTime, Image, ProcessId", "when, which program and which process created it"]]),
            r("Readable view of the events", f"/opt/sysmon/sysmonLogView < {c['sysmon']} | less",
              [["sysmonLogView", "ships with Sysmon for Linux: turns the XML into readable blocks"], ["< file", "read the log file"]],
              note="If the path differs on your system: dpkg -L sysmonforlinux | grep -i logview"),
            r("Sysmon configuration in use", "sudo sysmon -c",
              [["-c", "without a file: print the configuration Sysmon is running with"]], SUDO_RO,
              f"noxy's configuration lives in {sysmon.CONFIG}: file creation only, in home, temp, /etc, /opt, /usr/local, cron and systemd folders."),
        ],
        "vpn": [
            r("VPN state (noxy)", f"python3 {util.ROOT / 'noxy.py'} vpn status",
              [["vpn status", "tunnel, kill switch and installed configs; no sudo needed"]]),
            r("Tunnel details", "sudo wg show",
              [["wg show", "every WireGuard tunnel: endpoint, last handshake, bytes in and out"]], SUDO_RO),
            r("Kill switch (firewall defaults and rules)", "sudo ufw status verbose",
              [["Default: ... deny (outgoing)", "the kill switch is on"], ["noxy-vpn", "comment on the two rules that let the tunnel through"]], SUDO_RO),
            r("Which DNS servers are used", "resolvectl dns",
              [["resolvectl dns", "per interface; with the VPN on, the proton-* interface lists 10.2.0.1"]]),
            r("Public IP now", "curl -s https://api.ipify.org; echo",
              [["api.ipify.org", "answers with the address the internet sees (Proton's when the VPN is on)"]],
              note="This goes out from the VM like any request: through Proton when the VPN is on."),
            r("By hand: VPN on with a kill switch",
              "sudo ufw prepend allow out to <endpoint IP> port 51820 proto udp comment noxy-vpn && "
              "sudo ufw prepend allow out on proton-us comment noxy-vpn && sudo ufw default deny outgoing && sudo wg-quick up proton-us",
              [["ufw prepend", "rules go above the VM firewall's private-range blocks (Proton's DNS is 10.2.0.1)"],
               ["allow out to <endpoint>", "the only address reachable outside the tunnel: the Proton server"],
               ["default deny outgoing", "the kill switch"], ["wg-quick up", "bring the tunnel up from /etc/wireguard/proton-us.conf"]], CHANGES,
              "noxy.py vpn on does exactly this and checks the handshake."),
            r("By hand: VPN off", "sudo wg-quick down proton-us && sudo ufw default allow outgoing",
              [["wg-quick down", "tunnel down"], ["default allow outgoing", "kill switch off (the noxy-vpn rules can stay)"]], CHANGES),
        ],
        "artefacts": [
            r("npm runs (debug logs)", "grep -H 'verbose argv\\|verbose cwd' ~/.npm/_logs/*-debug-*.log",
              [["grep -H", "print the file name with each match"], ["verbose argv / cwd", "the exact npm command and folder"]]),
            r("New or changed files since the session start",
              f"find ~ /tmp /var/tmp /dev/shm -xdev -type f -newermt '{c['find_start']}' -not -path '*/.cache/*' 2>/dev/null | head -200",
              [["find", "walk folders"], ["-xdev", "stay on this file system"], ["-type f", "files only"],
               ["-newermt", "modified after this time (UTC)"], ["-not -path", "skip caches"],
               ["2>/dev/null", "hide permission errors"], ["| head -200", "first 200 results"]],
              note="An empty result is only meaningful if the paths are right: a typo also returns nothing."),
            r("Executables among them", f"find ~ /tmp /var/tmp /dev/shm -xdev -type f -perm -u+x -newermt '{c['find_start']}' 2>/dev/null",
              [["-perm -u+x", "owner may execute"]]),
        ],
        "net": [
            r("Merge the session's capture files", c["merge"],
              [["mergecap", "joins capture files in time order (Wireshark tools)"], ["-w", "output file"]],
              note="Every recipe below reads the merged file."),
            r("DNS queries", f"tshark -n -r {c['merged']} -Y 'dns.flags.response == 0' -T fields -e frame.time_utc -e dns.qry.name -e dns.qry.type",
              [["tshark", "Wireshark on the command line"], ["-n", "no name resolution: no DNS lookups of its own"],
               ["-r", "read a file"], ["-Y", "display filter: only DNS queries"], ["-T fields -e", "print just these fields"]],
              HOSTILE, tshark_note),
            r("HTTP requests with the full URI", f"tshark -n -r {c['merged']} -Y http.request -T fields -e frame.time_utc -e ip.dst -e tcp.dstport -e http.host -e http.request.uri",
              [["http.request", "only requests"], ["http.request.uri", "path and query string (where data exfiltration shows)"]],
              HOSTILE, tshark_note),
            r("TLS server names (SNI)", f"tshark -n -r {c['merged']} -Y 'tls.handshake.type == 1' -T fields -e frame.time_utc -e ip.dst -e tls.handshake.extensions_server_name",
              [["tls.handshake.type == 1", "ClientHello"], ["extensions_server_name", "the site name the client asked for"]],
              HOSTILE, tshark_note),
            r("New TCP connections", f"tshark -n -r {c['merged']} -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e frame.time_utc -e ip.dst -e tcp.dstport",
              [["syn == 1 && ack == 0", "the first packet of each connection"]], HOSTILE, tshark_note),
            r("Conversations summary", f"tshark -n -r {c['merged']} -q -z conv,tcp",
              [["-q", "no per-packet output"], ["-z conv,tcp", "one line per TCP conversation with bytes and duration"]],
              HOSTILE, tshark_note),
            r("Beacon timing to one destination", f"tshark -n -r {c['merged']} -Y 'ip.dst == 203.0.113.5 && tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e frame.time_delta_displayed",
              [["ip.dst == ...", "replace with the destination"], ["frame.time_delta_displayed", "seconds since the previous matching packet: a steady number is a beacon"]],
              HOSTILE, tshark_note),
        ],
        "iocs": [
            r("Unique domains asked", f"tshark -n -r {c['merged']} -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort | uniq -c | sort -rn",
              [["sort | uniq -c", "count each value"], ["sort -rn", "most frequent first"]], HOSTILE, tshark_note),
            r("Unique destination addresses", f"tshark -n -r {c['merged']} -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -e ip.dst | sort | uniq -c | sort -rn",
              [["ip.dst", "destination address of each new connection"]], HOSTILE, tshark_note),
        ],
        "disk": [
            r("Start fresh: delete the collected logs", f"sudo python3 {util.ROOT / 'noxy.py'} wipe --dry-run",
              [["wipe", "audit log (auditd rotates, old files deleted), captures (service stopped and started), Sysmon log, system journal"],
               ["--dry-run", "list what would go and how big it is; remove it to delete (asks you to type wipe)"],
               ["--keep-journal", "optional: leave the system journal alone"]], CHANGES,
              "Refuses while a session is open. Each wipe is logged in /var/lib/noxy/wipes.log. Sessions: python3 noxy.py session purge"),
            r("Sysmon log size", f"ls -lh {c['sysmon']}*",
              [["ls -lh", "the file-creation log and its rotations (10 x 50 MB at most)"]]),
            r("Free space", f"df -h / {c['audit']} {c['pcap_dir']}",
              [["df", "disk free per file system"], ["-h", "human sizes"]]),
            r("What noxy's sources use", f"sudo du -sh {c['audit']} {c['pcap_dir']} ~/noxy/data",
              [["du", "disk usage of folders"], ["-s", "one total per folder"], ["-h", "human sizes"]], SUDO_RO),
            r("Oldest and newest captures", f"ls -lhtr {c['pcap_dir']} | head -3; ls -lht {c['pcap_dir']} | head -3",
              [["-tr", "oldest first"], ["-t", "newest first"]]),
            r("Audit log files", f"sudo ls -lh {c['audit']}",
              [["ls -lh", "the 10 rotating files of up to 50 MB each"]], SUDO_RO),
        ],
        "services": [
            r("noxy itself", "systemctl --user status noxy --no-pager; journalctl --user -u noxy -n 50 --no-pager",
              [["--user", "your own services (noxy runs as you)"], ["journalctl -u noxy -n 50", "noxy's last 50 log lines"]]),
            r("Restart or stop noxy", "systemctl --user restart noxy    # or: stop, start",
              [["restart", "stop and start again"]], CHANGES),
            r("Capture service control", "sudo systemctl restart noxy-capture    # or: stop, start",
              [["sudo systemctl", "system services need root (noxy uses a polkit rule for this one service)"]], CHANGES,
              "A stop shows as a coverage gap in the sessions it overlaps."),
            r("Capture service log", "sudo journalctl -u noxy-capture -n 30 --no-pager",
              [["-u noxy-capture", "only this service"], ["-n 30", "last 30 lines"]], SUDO_RO),
            r("Sysmon service log", "sudo journalctl -u sysmon -n 30 --no-pager",
              [["-u sysmon", "Sysmon's own service messages (start, configuration errors)"]], SUDO_RO),
            r("auditd state", "sudo auditctl -s",
              [["-s", "status: enabled, lost events, backlog (lost > 0 means missed records)"]], SUDO_RO),
        ],
    }


TITLES = {"status": "lab status", "exec": "executions", "connections": "connections", "persistence": "persistence and editor",
          "files": "file creation", "vpn": "vpn", "artefacts": "artefacts", "net": "network", "iocs": "indicators", "disk": "disk",
          "services": "services"}


def recipes(topic, session=None, pcap_files=None):
    all_topics = topics(context(session, pcap_files))
    if topic == "all":
        return [{"topic": t, "title": TITLES[t], "recipes": rs} for t, rs in all_topics.items()]
    if topic not in all_topics:
        raise KeyError(topic)
    return [{"topic": topic, "title": TITLES[topic], "recipes": all_topics[topic]}]
