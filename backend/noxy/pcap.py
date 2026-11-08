"""Pure-Python reader for classic pcap files: DNS queries, HTTP requests, TLS SNI, TCP connection starts, UDP flows.

Why not tshark: captures are attacker-controlled input. Wireshark's C dissectors have a long CVE history; this
reader is memory-safe, bounds-checks every field, needs no dependency and is easy to test. It extracts only what
noxy shows. For deep packet work, open the capture in Wireshark yourself.
"""
import ipaddress
import re
import struct

MAX_RECORD = 262144
HTTP_RE = re.compile(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) (\S{1,8192}) HTTP/\d\.\d\r?\n")
UDP_IGNORE = {53, 67, 68, 123, 137, 138, 1900, 5353, 5355}
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
          64: "SVCB", 65: "HTTPS", 255: "ANY"}
TLS_FIRST_BYTES = 16384


class PcapError(Exception):
    pass


def _records(fh):
    head = fh.read(24)
    if len(head) < 24:
        return
    magic = head[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        raise PcapError("pcapng format is not supported: convert with `editcap -F pcap in.pcapng out.pcap`")
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise PcapError("not a pcap file")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", head[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    div = 1e9 if nano else 1e6
    while True:
        h = fh.read(16)
        if len(h) < 16:
            return
        sec, frac, incl, _orig = rec.unpack(h)
        if incl > MAX_RECORD:
            return                                   # corrupt or hostile length: stop reading this file
        data = fh.read(incl)
        if len(data) < incl:
            return                                   # file still being written
        yield sec + frac / div, linktype, data


def _l3(linktype, d):
    """Returns (ethertype-ish 'v4'/'v6', payload) or (None, None)."""
    try:
        if linktype == 1:                            # Ethernet
            off, etype = 14, struct.unpack(">H", d[12:14])[0]
            while etype in (0x8100, 0x88A8):
                etype = struct.unpack(">H", d[off + 2:off + 4])[0]
                off += 4
        elif linktype == 113:                        # Linux cooked v1
            off, etype = 16, struct.unpack(">H", d[14:16])[0]
        elif linktype == 276:                        # Linux cooked v2
            off, etype = 20, struct.unpack(">H", d[0:2])[0]
        elif linktype in (101, 12, 14):              # raw IP
            v = d[0] >> 4
            return ("v4" if v == 4 else "v6" if v == 6 else None), d
        elif linktype == 228:
            return "v4", d
        elif linktype == 229:
            return "v6", d
        elif linktype == 0:                          # BSD loopback
            fam = struct.unpack("<I", d[:4])[0]
            return ("v4" if fam == 2 else "v6" if fam in (24, 28, 30) else None), d[4:]
        else:
            return None, None
    except (struct.error, IndexError):
        return None, None
    return ("v4" if etype == 0x0800 else "v6" if etype == 0x86DD else None), d[off:]


def _l4(ver, p):
    """Returns (proto, src, dst, l4 bytes) or None. Non-first IPv4 fragments are skipped."""
    try:
        if ver == "v4":
            ihl = (p[0] & 0x0F) * 4
            total = struct.unpack(">H", p[2:4])[0]
            frag = struct.unpack(">H", p[6:8])[0] & 0x1FFF
            if frag or ihl < 20:
                return None
            proto = p[9]
            src, dst = str(ipaddress.IPv4Address(p[12:16])), str(ipaddress.IPv4Address(p[16:20]))
            end = total if 0 < total <= len(p) else len(p)
            return proto, src, dst, p[ihl:end]
        if ver == "v6":
            nh, off = p[6], 40
            plen = struct.unpack(">H", p[4:6])[0]
            src = ipaddress.IPv6Address(p[8:24])
            dst = ipaddress.IPv6Address(p[24:40])
            for _ in range(8):
                if nh in (0, 43, 60):
                    nh, off = p[off], off + (p[off + 1] + 1) * 8
                elif nh == 44:
                    if struct.unpack(">H", p[off + 2:off + 4])[0] & 0xFFF8:
                        return None
                    nh, off = p[off], off + 8
                else:
                    break
            s = str(src.ipv4_mapped or src.compressed)
            t = str(dst.ipv4_mapped or dst.compressed)
            end = 40 + plen if 0 < 40 + plen <= len(p) else len(p)
            return nh, s, t, p[off:end]
    except (struct.error, IndexError, ValueError):
        return None
    return None


def parse_dns_query(b):
    """UDP payload -> (qname, qtype) for a query, else None."""
    if len(b) < 17:
        return None
    flags, qd = struct.unpack(">HH", b[2:6])
    if flags & 0x8000 or qd < 1:
        return None
    labels, i = [], 12
    while i < len(b):
        n = b[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 or n > 63 or i + 1 + n > len(b):
            return None
        labels.append(b[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
        if sum(len(x) + 1 for x in labels) > 255:
            return None
    else:
        return None
    if i + 2 > len(b):
        return None
    qtype = struct.unpack(">H", b[i:i + 2])[0]
    return ".".join(labels).lower() or ".", QTYPES.get(qtype, str(qtype))


def parse_sni(b):
    """First bytes of a TCP stream -> SNI from a TLS ClientHello, else None."""
    try:
        if len(b) < 9 or b[0] != 0x16 or b[5] != 0x01:
            return None
        i = 5 + 4 + 2 + 32                           # handshake header, version, random
        i += 1 + b[i]                                # session id
        i += 2 + struct.unpack(">H", b[i:i + 2])[0]  # cipher suites
        i += 1 + b[i]                                # compression
        end = i + 2 + struct.unpack(">H", b[i:i + 2])[0]
        i += 2
        while i + 4 <= min(end, len(b)):
            etype, elen = struct.unpack(">HH", b[i:i + 4])
            if etype == 0:
                j = i + 4 + 2
                if b[j] == 0:
                    n = struct.unpack(">H", b[j + 1:j + 3])[0]
                    name = b[j + 3:j + 3 + n]
                    if len(name) == n and 0 < n <= 255:
                        return name.decode("ascii", "replace").lower()
                return None
            i += 4 + elen
    except (IndexError, struct.error):
        return None
    return None


def parse_http(b):
    """TCP payload starting a request -> (method, uri, host, ua), else None."""
    m = HTTP_RE.match(b[:8400])
    if not m:
        return None
    head = b[m.end():m.end() + 8192].split(b"\r\n\r\n", 1)[0]
    host = ua = ""
    for line in head.split(b"\n")[:100]:
        k, _, v = line.partition(b":")
        k = k.strip().lower()
        if k == b"host":
            host = v.strip().decode("latin-1")[:255]
        elif k == b"user-agent":
            ua = v.strip().decode("latin-1")[:512]
    return m.group(1).decode(), m.group(2).decode("latin-1"), host, ua


def parse_file(path, since=None, until=None):
    """Returns dict of lists: syn, dns, http, tls, udp (aggregated). Raises PcapError / OSError."""
    out = {"syn": [], "dns": [], "http": [], "tls": [], "udp": {}, "packets": 0, "first": None, "last": None}
    streams = {}
    with open(path, "rb") as fh:
        for ts, lt, data in _records(fh):
            if (since and ts < since) or (until and ts > until):
                continue
            out["packets"] += 1
            out["first"] = ts if out["first"] is None else out["first"]
            out["last"] = ts
            ver, l3 = _l3(lt, data)
            if not ver:
                continue
            r = _l4(ver, l3)
            if not r:
                continue
            proto, src, dst, l4 = r
            if proto == 6 and len(l4) >= 20:
                sport, dport, seq = struct.unpack(">HHI", l4[:8])
                off = (l4[12] >> 4) * 4
                flags = l4[13]
                if flags & 0x02 and not flags & 0x10:
                    out["syn"].append({"ts": ts, "src": src, "sport": sport, "dst": dst, "dport": dport})
                payload = l4[off:]
                if payload:
                    h = parse_http(payload) if payload[:1].isalpha() else None
                    if h:
                        out["http"].append({"ts": ts, "src": src, "sport": sport, "dst": dst, "dport": dport,
                                            "method": h[0], "uri": h[1], "name": h[2], "ua": h[3]})
                    key = (src, sport, dst, dport)
                    st = streams.get(key)
                    if st is None and payload[:1] == b"\x16":
                        st = streams[key] = {"ts": ts, "segs": {}, "size": 0}
                    if st is not None and st["size"] < TLS_FIRST_BYTES and seq not in st["segs"]:
                        st["segs"][seq] = payload
                        st["size"] += len(payload)
            elif proto == 17 and len(l4) >= 8:
                sport, dport = struct.unpack(">HH", l4[:4])
                payload = l4[8:]
                if dport == 53:
                    q = parse_dns_query(payload)
                    if q:
                        out["dns"].append({"ts": ts, "src": src, "dst": dst, "dport": dport, "name": q[0], "qtype": q[1]})
                elif dport not in UDP_IGNORE and sport not in (53, 5353, 67, 68):
                    k = (src, dst, dport)
                    a = out["udp"].get(k)
                    if a:
                        a["count"] += 1
                        a["last_ts"] = ts
                    else:
                        out["udp"][k] = {"ts": ts, "src": src, "dst": dst, "dport": dport, "count": 1, "last_ts": ts}
    for (src, sport, dst, dport), st in streams.items():
        segs = sorted(st["segs"].items())
        buf, nxt = b"", None
        for seq, pl in segs:
            if nxt is None or seq == nxt:
                buf += pl
                nxt = (seq + len(pl)) & 0xFFFFFFFF
            elif seq > nxt:
                break
        sni = parse_sni(buf)
        if sni:
            out["tls"].append({"ts": st["ts"], "src": src, "sport": sport, "dst": dst, "dport": dport, "name": sni})
    out["udp"] = list(out["udp"].values())
    return out


# ------------------------------------------------------------------ writer (tests and fixtures only)

def write_pcap(path, packets, linktype=1):
    """packets: list of (ts, bytes). Classic pcap, microsecond resolution."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts, data in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)
