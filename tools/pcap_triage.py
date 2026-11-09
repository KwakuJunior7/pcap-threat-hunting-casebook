#!/usr/bin/env python3
"""
pcap_triage.py - first-pass triage of a packet capture.

Answers the questions I ask at the start of every PCAP investigation:
  * Which internal hosts are in the capture (IP, MAC, hostname)?
  * Which user accounts are logging in (Kerberos)?
  * Which servers look like domain controllers?
  * Is there suspicious web traffic (raw-IP hosts, missing User-Agent,
    executable downloads, IP-geolocation lookups)?
  * Where are internal hosts connecting externally (TCP, TLS SNI, DNS)?

Pure Python standard library - no Wireshark/tshark install required.
Reads classic libpcap (.pcap) and pcapng files, Ethernet / Linux SLL / raw IPv4.

Usage:
    python pcap_triage.py capture.pcap                  # markdown report to stdout
    python pcap_triage.py capture.pcap -o report.md --iocs iocs.csv --json out.json
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Packet readers
# --------------------------------------------------------------------------- #

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228


def read_pcap(path: str):
    """Yield (timestamp_float, linktype, frame_bytes) from a .pcap or .pcapng file."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        fh.seek(0)
        if head == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(fh)
        else:
            yield from _read_classic(fh)


def _read_classic(fh):
    gh = fh.read(24)
    if len(gh) < 24:
        raise ValueError("file too short to be a pcap")
    magic = gh[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("not a pcap/pcapng file (bad magic)")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", gh[20:24])[0] & 0x0FFFFFFF
    div = 1e9 if nano else 1e6
    while True:
        rh = fh.read(16)
        if len(rh) < 16:
            return
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", rh)
        data = fh.read(incl)
        if len(data) < incl:
            return
        yield sec + frac / div, linktype, data


def _read_pcapng(fh):
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, ticks_per_second)
    while True:
        bh = fh.read(8)
        if len(bh) < 8:
            return
        btype_raw, blen_raw = bh[:4], bh[4:]
        if btype_raw == b"\x0a\x0d\x0d\x0a":  # Section Header Block
            bom = fh.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", blen_raw)[0]
            fh.read(blen - 12)
            interfaces = []
            continue
        btype = struct.unpack(endian + "I", btype_raw)[0]
        blen = struct.unpack(endian + "I", blen_raw)[0]
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]  # trailing block length
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            tps = 1e6
            opts = body[8:]
            i = 0
            while i + 4 <= len(opts):
                code, olen = struct.unpack(endian + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    v = opts[i + 4]
                    tps = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                i += 4 + ((olen + 3) & ~3)
            interfaces.append((linktype, tps))
        elif btype == 6:  # Enhanced Packet Block
            ifid, ts_hi, ts_lo, cap_len, _orig = struct.unpack(endian + "IIIII", body[:20])
            linktype, tps = interfaces[ifid] if ifid < len(interfaces) else (LINKTYPE_ETHERNET, 1e6)
            yield ((ts_hi << 32) | ts_lo) / tps, linktype, body[20:20 + cap_len]
        elif btype == 3:  # Simple Packet Block
            linktype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            yield 0.0, linktype, body[4:]


# --------------------------------------------------------------------------- #
# Protocol decoding
# --------------------------------------------------------------------------- #


@dataclass
class Pkt:
    no: int
    ts: float
    src_mac: str | None
    dst_mac: str | None
    src: str
    dst: str
    proto: str  # "tcp" | "udp" | "other"
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0
    payload: bytes = b""


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def decode(no: int, ts: float, linktype: int, data: bytes) -> Pkt | None:
    src_mac = dst_mac = None
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        dst_mac, src_mac = _mac(data[0:6]), _mac(data[6:12])
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:  # VLAN tags
            etype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        if etype != 0x0800:
            return None
        ip = data[off:]
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16 or struct.unpack("!H", data[14:16])[0] != 0x0800:
            return None
        ip = data[16:]
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4):
        ip = data
    else:
        return None

    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0] or len(ip)
    frag_off = struct.unpack("!H", ip[6:8])[0] & 0x1FFF
    proto_n = ip[9]
    src = str(ipaddress.IPv4Address(ip[12:16]))
    dst = str(ipaddress.IPv4Address(ip[16:20]))
    seg = ip[ihl:total]
    pkt = Pkt(no, ts, src_mac, dst_mac, src, dst, "other")
    if frag_off:
        return pkt
    if proto_n == 6 and len(seg) >= 20:
        pkt.proto = "tcp"
        pkt.sport, pkt.dport = struct.unpack("!HH", seg[:4])
        doff = (seg[12] >> 4) * 4
        pkt.tcp_flags = seg[13]
        pkt.payload = seg[doff:]
    elif proto_n == 17 and len(seg) >= 8:
        pkt.proto = "udp"
        pkt.sport, pkt.dport = struct.unpack("!HH", seg[:4])
        pkt.payload = seg[8:]
    return pkt


# ---- DNS / LLMNR / mDNS --------------------------------------------------- #

def _dns_name(buf: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped_end = None
    while off < len(buf):
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(buf) or depth > 10:
                raise ValueError("bad pointer")
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if jumped_end is None:
                jumped_end = off + 2
            name, _ = _dns_name(buf, ptr, depth + 1)
            if name:
                labels.append(name)
            off = jumped_end
            return ".".join(labels), off
        labels.append(buf[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return ".".join(labels), (jumped_end or off)


def parse_dns(payload: bytes) -> dict | None:
    if len(payload) < 12:
        return None
    _tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
    opcode = (flags >> 11) & 0xF
    is_resp = bool(flags & 0x8000)
    off = 12
    questions, records = [], []
    try:
        for _ in range(qd):
            name, off = _dns_name(payload, off)
            qtype = struct.unpack("!H", payload[off:off + 2])[0]
            off += 4
            questions.append((name, qtype))
        for _ in range(an + ns + ar):
            name, off = _dns_name(payload, off)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", payload[off:off + 10])
            off += 10
            rdata = payload[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                records.append((name, "A", str(ipaddress.IPv4Address(rdata))))
    except (ValueError, struct.error, IndexError):
        pass
    return {"opcode": opcode, "response": is_resp, "questions": questions, "records": records}


# ---- NetBIOS Name Service ------------------------------------------------- #

def _nb_decode(encoded: str) -> tuple[str, int] | None:
    if len(encoded) != 32:
        return None
    raw = bytes(((ord(encoded[i]) - 65) << 4) | (ord(encoded[i + 1]) - 65) for i in range(0, 32, 2))
    return raw[:15].decode("ascii", "replace").rstrip(), raw[15]


def parse_nbns(payload: bytes) -> dict | None:
    if len(payload) < 12:
        return None
    flags = struct.unpack("!H", payload[2:4])[0]
    opcode = (flags >> 11) & 0xF
    try:
        enc, _ = _dns_name(payload, 12)
    except ValueError:
        return None
    dec = _nb_decode(enc.split(".")[0])
    if not dec:
        return None
    return {"opcode": opcode, "response": bool(flags & 0x8000), "name": dec[0], "suffix": dec[1]}


# ---- DHCP ----------------------------------------------------------------- #

def parse_dhcp(payload: bytes) -> dict | None:
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    out = {"mac": _mac(payload[28:34])}
    i = 240
    while i < len(payload):
        code = payload[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        ln = payload[i + 1]
        val = payload[i + 2:i + 2 + ln]
        if code == 12:
            out["hostname"] = val.decode("ascii", "replace")
        elif code == 50 and ln == 4:
            out["requested_ip"] = str(ipaddress.IPv4Address(val))
        elif code == 53 and ln == 1:
            out["msg_type"] = val[0]
        i += 2 + ln
    return out


# ---- Kerberos (minimal DER walker) ---------------------------------------- #

def _der(buf: bytes, off: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) for the TLV at off."""
    tag = buf[off]
    ln = buf[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    if off + ln > len(buf):
        raise ValueError("truncated")
    return tag, off, off + ln


def _der_children(buf: bytes, start: int, end: int) -> dict[int, tuple[int, int]]:
    """Map context tag number -> (content_start, content_end) of a SEQUENCE's [n] children."""
    out = {}
    off = start
    while off < end:
        tag, cs, ce = _der(buf, off)
        if tag & 0xE0 == 0xA0:
            out[tag & 0x1F] = (cs, ce)
        off = ce
    return out


def _der_string(buf: bytes, cs: int, ce: int) -> str:
    _tag, s, e = _der(buf, cs)
    return buf[s:e].decode("utf-8", "replace")


def _principal(buf: bytes, cs: int, ce: int) -> str:
    _t, ss, se = _der(buf, cs)  # PrincipalName SEQUENCE
    kids = _der_children(buf, ss, se)
    if 1 not in kids:
        return ""
    _t, ls, le = _der(buf, kids[1][0])  # SEQUENCE OF KerberosString
    parts, off = [], ls
    while off < le:
        _t, s, e = _der(buf, off)
        parts.append(buf[s:e].decode("utf-8", "replace"))
        off = e
    return "/".join(parts)


KRB_MSG = {0x6A: "AS-REQ", 0x6B: "AS-REP", 0x6C: "TGS-REQ", 0x6D: "TGS-REP"}


def parse_kerberos(payload: bytes, over_tcp: bool) -> dict | None:
    buf = payload[4:] if over_tcp else payload
    if not buf or buf[0] not in KRB_MSG:
        return None
    msg = KRB_MSG[buf[0]]
    try:
        _t, cs, ce = _der(buf, 0)
        _t, ss, se = _der(buf, cs)  # inner SEQUENCE
        kids = _der_children(buf, ss, se)
        cname = realm = ""
        if msg in ("AS-REQ", "TGS-REQ") and 4 in kids:
            _t, bs, be = _der(buf, kids[4][0])
            body = _der_children(buf, bs, be)
            if 1 in body:
                cname = _principal(buf, *body[1])
            if 2 in body:
                realm = _der_string(buf, *body[2])
        elif msg in ("AS-REP", "TGS-REP"):
            if 4 in kids:
                cname = _principal(buf, *kids[4])
            if 3 in kids:
                realm = _der_string(buf, *kids[3])
    except (ValueError, IndexError):
        return {"msg": msg, "cname": "", "realm": ""}
    return {"msg": msg, "cname": cname, "realm": realm}


# ---- HTTP & TLS ----------------------------------------------------------- #

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def parse_http_request(payload: bytes) -> dict | None:
    if not payload.startswith(HTTP_METHODS):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 3:
        return None
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"method": parts[0], "uri": parts[1], "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent"), "headers": list(headers)}


def parse_tls_sni(payload: bytes) -> str | None:
    # TLS record: 0x16 handshake, version, len, then handshake type 1 (ClientHello)
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    try:
        off = 9 + 2 + 32  # record(5)+hs header(4) + client_version(2) + random(32)
        off += 1 + payload[off]  # session id
        cs_len = struct.unpack("!H", payload[off:off + 2])[0]
        off += 2 + cs_len
        off += 1 + payload[off]  # compression methods
        ext_end = off + 2 + struct.unpack("!H", payload[off:off + 2])[0]
        off += 2
        while off + 4 <= ext_end:
            etype, elen = struct.unpack("!HH", payload[off:off + 4])
            if etype == 0:  # server_name
                name_len = struct.unpack("!H", payload[off + 7:off + 9])[0]
                return payload[off + 9:off + 9 + name_len].decode("ascii", "replace")
            off += 4 + elen
    except (struct.error, IndexError):
        return None
    return None


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

IP_LOOKUP_DOMAINS = {
    "ip-api.com", "ipinfo.io", "api.ipify.org", "ipify.org", "checkip.amazonaws.com",
    "icanhazip.com", "ifconfig.me", "myexternalip.com", "wtfismyip.com", "ipwho.is",
    "freegeoip.app", "ipapi.co", "api.myip.com", "ip.anysrc.net", "checkip.dyndns.org",
}
RISKY_EXT = re.compile(r"\.(exe|dll|scr|ps1|psm1|hta|vbs|vbe|js|jse|wsf|bat|cmd|msi|zip|rar|7z|iso|img|lnk|bin|dat)(\?|$)", re.I)
NOISY_DST = {"239.255.255.250", "224.0.0.252", "224.0.0.251", "255.255.255.255"}


# "Internal" = RFC 1918 private space + link-local. (Python's is_private also
# includes documentation ranges like 203.0.113.0/24, which we treat as external.)
INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")]


def is_internal(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return any(a in n for n in INTERNAL_NETS)


def is_routable_external(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return not (is_internal(ip) or a.is_multicast or a.is_loopback or a.is_reserved
                or a.is_unspecified or ip == "255.255.255.255" or a in ipaddress.ip_network("100.64.0.0/10"))


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split(":")[0].strip("[]"))
        return True
    except ValueError:
        return False


@dataclass
class Host:
    ip: str
    macs: Counter = field(default_factory=Counter)
    hostnames: set = field(default_factory=set)
    users: set = field(default_factory=set)
    machine_accounts: set = field(default_factory=set)
    first_seen: float | None = None


class Triage:
    def __init__(self) -> None:
        self.hosts: dict[str, Host] = {}
        self.packets = 0
        self.t0: float | None = None
        self.t_last: float | None = None
        self.kerberos_events: list[dict] = []
        self.http: list[dict] = []
        self.sni: Counter = Counter()
        self.sni_first: dict[str, tuple[int, str]] = {}
        self.dns_queries: Counter = Counter()
        self.ext_conns: dict[tuple[str, int], dict] = {}
        self.server_ports: dict[str, set] = defaultdict(set)
        self.realms: set = set()

    # -- helpers ---------------------------------------------------------- #
    def host(self, ip: str) -> Host:
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = Host(ip)
        return h

    def rel(self, ts: float) -> float:
        return ts - (self.t0 or ts)

    # -- main loop -------------------------------------------------------- #
    def feed(self, p: Pkt) -> None:
        self.packets += 1
        if self.t0 is None:
            self.t0 = p.ts
        self.t_last = p.ts

        if is_internal(p.src) and p.src != "0.0.0.0":
            h = self.host(p.src)
            if p.src_mac:
                h.macs[p.src_mac] += 1
            if h.first_seen is None:
                h.first_seen = self.rel(p.ts)

        if p.proto not in ("tcp", "udp"):
            return
        ports = {p.sport, p.dport}

        # Servers: internal destinations answering on identity / file-sharing ports
        if is_internal(p.dst) and p.dport in (53, 88, 389, 445, 636, 3268):
            self.server_ports[p.dst].add(p.dport)

        if p.proto == "udp" and ports & {53, 5353, 5355}:
            self._dns(p)
        if p.proto == "udp" and 137 in ports:
            self._nbns(p)
        if p.proto == "udp" and ports & {67, 68}:
            self._dhcp(p)
        if 88 in ports and p.payload:
            self._kerberos(p)
        if p.proto == "tcp" and p.payload:
            req = parse_http_request(p.payload)
            if req:
                self._http(p, req)
            else:
                sni = parse_tls_sni(p.payload)
                if sni:
                    self.sni[sni] += 1
                    self.sni_first.setdefault(sni, (p.no, p.src))
        # External TCP connection attempts (SYN without ACK) from internal hosts
        if (p.proto == "tcp" and p.tcp_flags & 0x02 and not p.tcp_flags & 0x10
                and is_internal(p.src) and is_routable_external(p.dst)):
            key = (p.dst, p.dport)
            c = self.ext_conns.setdefault(key, {"count": 0, "first": p.no, "first_t": self.rel(p.ts),
                                                "sources": set()})
            c["count"] += 1
            c["sources"].add(p.src)

    def _dns(self, p: Pkt) -> None:
        d = parse_dns(p.payload)
        if not d:
            return
        if d["opcode"] == 5:  # Dynamic update: host registering its own A record
            for name, rtype, value in d["records"]:
                if rtype == "A" and is_internal(value):
                    self.host(value).hostnames.add(name)
            return
        if not d["response"]:
            for name, qtype in d["questions"]:
                if p.dport == 5355 and is_internal(p.src):  # LLMNR
                    continue
                if name and not name.endswith((".arpa", ".local")):
                    self.dns_queries[name.lower()] += 1

    def _nbns(self, p: Pkt) -> None:
        n = parse_nbns(p.payload)
        # opcode 5 = registration, 8 = refresh; suffix 0x00 = workstation name
        if n and not n["response"] and n["opcode"] in (5, 8) and n["suffix"] == 0x00 \
                and is_internal(p.src):
            self.host(p.src).hostnames.add(n["name"])

    def _dhcp(self, p: Pkt) -> None:
        d = parse_dhcp(p.payload)
        if not d or "hostname" not in d:
            return
        ip = d.get("requested_ip") or (p.src if p.src != "0.0.0.0" else None)
        if ip and is_internal(ip):
            h = self.host(ip)
            h.hostnames.add(d["hostname"])
            h.macs[d["mac"]] += 0  # record without inflating counts

    def _kerberos(self, p: Pkt) -> None:
        k = parse_kerberos(p.payload, p.proto == "tcp")
        if not k or not k["cname"]:
            return
        client = p.src if k["msg"].endswith("REQ") else p.dst
        kdc = p.dst if k["msg"].endswith("REQ") else p.src
        if k["realm"]:
            self.realms.add(k["realm"].upper())
        if is_internal(client):
            h = self.host(client)
            (h.machine_accounts if k["cname"].endswith("$") else h.users).add(k["cname"])
        self.kerberos_events.append({"frame": p.no, "time": round(self.rel(p.ts), 3), "msg": k["msg"],
                                     "client": client, "kdc": kdc, "account": k["cname"],
                                     "realm": k["realm"]})

    def _http(self, p: Pkt, req: dict) -> None:
        reasons = []
        host = req["host"]
        bare = host.split(":")[0].lower()
        if not host:
            reasons.append("no Host header")
        elif _is_ip_literal(host) and not is_internal(bare):
            reasons.append("Host header is a raw external IP (no domain name)")
        if req["user_agent"] is None:
            reasons.append("no User-Agent header (browsers always send one)")
        if bare in IP_LOOKUP_DOMAINS or any(bare.endswith("." + d) for d in IP_LOOKUP_DOMAINS):
            reasons.append("public IP / geolocation lookup service (common malware & infostealer check-in)")
        if RISKY_EXT.search(req["uri"]):
            reasons.append("request for an executable/script/archive file type")
        if p.dst in NOISY_DST:
            return  # SSDP and similar multicast HTTP-over-UDP noise never arrives here, but be safe
        self.http.append({"frame": p.no, "time": round(self.rel(p.ts), 3), "src": p.src,
                          "dst": f"{p.dst}:{p.dport}", "method": req["method"], "host": host,
                          "uri": req["uri"], "user_agent": req["user_agent"],
                          "suspicious": bool(reasons), "reasons": reasons})

    # -- results ---------------------------------------------------------- #
    def domain_controllers(self) -> list[str]:
        return sorted((ip for ip, ports in self.server_ports.items() if {88, 389} <= ports),
                      key=ipaddress.ip_address)

    def summary(self, source: str) -> dict:
        dcs = set(self.domain_controllers())
        for ip in self.server_ports:  # servers we only ever saw as a destination
            self.host(ip)
        hosts = []
        for ip in sorted(self.hosts, key=ipaddress.ip_address):
            h = self.hosts[ip]
            if ip.endswith(".255") or ip in ("0.0.0.0",):
                continue
            hosts.append({
                "ip": ip,
                "mac": h.macs.most_common(1)[0][0] if h.macs else None,
                "hostnames": sorted(h.hostnames, key=str.lower),
                "users": sorted(h.users, key=str.lower),
                "machine_accounts": sorted(h.machine_accounts, key=str.lower),
                "role": "domain controller (Kerberos + LDAP)" if ip in dcs else (
                    "server (" + ",".join(map(str, sorted(self.server_ports[ip]))) + ")"
                    if ip in self.server_ports else "client"),
            })
        start = dt.datetime.fromtimestamp(self.t0, dt.timezone.utc).isoformat() if self.t0 else None
        end = dt.datetime.fromtimestamp(self.t_last, dt.timezone.utc).isoformat() if self.t_last else None
        ext = sorted(self.ext_conns.items(), key=lambda kv: (-kv[1]["count"], kv[1]["first"]))
        return {
            "source": source,
            "packets": self.packets,
            "first_packet_utc": start,
            "last_packet_utc": end,
            "duration_s": round((self.t_last or 0) - (self.t0 or 0), 3),
            "realms": sorted(self.realms),
            "domain_controllers": sorted(dcs, key=ipaddress.ip_address),
            "hosts": hosts,
            "kerberos": self.kerberos_events,
            "http": self.http,
            "tls_sni": [{"server_name": n, "count": c, "first_frame": self.sni_first[n][0],
                         "client": self.sni_first[n][1]} for n, c in self.sni.most_common()],
            "dns_queries": [{"name": n, "count": c} for n, c in self.dns_queries.most_common()],
            "external_tcp": [{"dst": d, "port": port, "syn_count": v["count"], "first_frame": v["first"],
                              "first_time": round(v["first_t"], 3), "sources": sorted(v["sources"])}
                             for (d, port), v in ext],
        }


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def iocs(s: dict) -> list[dict]:
    out, seen = [], set()

    def add(kind, value, context, frame):
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.append({"type": kind, "value": value, "context": context, "first_frame": frame})

    for r in s["http"]:
        if r["suspicious"]:
            ip = r["dst"].split(":")[0]
            add("ip", ip, "; ".join(r["reasons"]), r["frame"])
            add("url", f"http://{r['host']}{r['uri']}", f"{r['method']} from {r['src']}", r["frame"])
            if not _is_ip_literal(r["host"]):
                add("domain", r["host"].split(":")[0], "suspicious HTTP request", r["frame"])
    return out


def _md_table(headers: list[str], rows: list[list]) -> str:
    def cell(v):
        return str(v if v not in (None, "") else "-").replace("|", "\\|")
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def to_markdown(s: dict, top: int = 15) -> str:
    out = [f"# PCAP triage report: `{s['source']}`", ""]
    out.append(_md_table(["Packets", "First packet (UTC)", "Last packet (UTC)", "Duration (s)", "Kerberos realm(s)"],
                         [[s["packets"], s["first_packet_utc"], s["last_packet_utc"], s["duration_s"],
                           ", ".join(s["realms"])]]))
    out += ["", "## Internal hosts", ""]
    out.append(_md_table(["IP", "MAC", "Hostname(s)", "User account(s)", "Machine account(s)", "Role"],
                         [[h["ip"], h["mac"], ", ".join(h["hostnames"]), ", ".join(h["users"]),
                           ", ".join(h["machine_accounts"]), h["role"]] for h in s["hosts"]]))

    sus = [r for r in s["http"] if r["suspicious"]]
    out += ["", f"## Suspicious HTTP requests ({len(sus)})", ""]
    if sus:
        out.append(_md_table(["Frame", "Time (s)", "Source", "Destination", "Request", "User-Agent", "Why flagged"],
                             [[r["frame"], r["time"], r["src"], r["dst"], f"{r['method']} {r['host']}{r['uri']}",
                               r["user_agent"], "; ".join(r["reasons"])] for r in sus]))
    else:
        out.append("None flagged.")

    out += ["", "## Kerberos authentications", ""]
    if s["kerberos"]:
        out.append(_md_table(["Frame", "Time (s)", "Message", "Client", "KDC", "Account", "Realm"],
                             [[k["frame"], k["time"], k["msg"], k["client"], k["kdc"], k["account"], k["realm"]]
                              for k in s["kerberos"][:top * 2]]))
    else:
        out.append("No Kerberos client names found.")

    out += ["", f"## External TCP destinations (top {top} by SYN count)", ""]
    out.append(_md_table(["Destination", "Port", "SYNs", "First frame", "First time (s)", "Internal source(s)"],
                         [[e["dst"], e["port"], e["syn_count"], e["first_frame"], e["first_time"],
                           ", ".join(e["sources"])] for e in s["external_tcp"][:top]]) if s["external_tcp"] else "None.")

    out += ["", f"## TLS server names (SNI, top {top})", ""]
    out.append(_md_table(["Server name", "ClientHellos", "First frame", "Client"],
                         [[t["server_name"], t["count"], t["first_frame"], t["client"]]
                          for t in s["tls_sni"][:top]]) if s["tls_sni"] else "None.")

    out += ["", f"## DNS queries (top {top})", ""]
    out.append(_md_table(["Name", "Queries"], [[d["name"], d["count"]] for d in s["dns_queries"][:top]])
               if s["dns_queries"] else "None.")

    all_http = [r for r in s["http"] if not r["suspicious"]]
    if all_http:
        out += ["", f"## Other HTTP requests ({len(all_http)})", ""]
        out.append(_md_table(["Frame", "Source", "Request", "User-Agent"],
                             [[r["frame"], r["src"], f"{r['method']} {r['host']}{r['uri']}", r["user_agent"]]
                              for r in all_http[:top]]))
    out += ["", "---", "_Generated by `pcap_triage.py`. Findings are leads for manual verification in Wireshark, "
            "not conclusions._", ""]
    return "\n".join(out)


def run(path: str) -> dict:
    t = Triage()
    for no, (ts, lt, data) in enumerate(read_pcap(path), start=1):
        p = decode(no, ts, lt, data)
        if p:
            t.feed(p)
        else:
            t.packets += 1
    return t.summary(path.replace("\\", "/").split("/")[-1])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="First-pass triage of a .pcap/.pcapng file.")
    ap.add_argument("pcap")
    ap.add_argument("-o", "--output", help="write markdown report here (default: stdout)")
    ap.add_argument("--json", help="also write full results as JSON")
    ap.add_argument("--iocs", help="also write indicators of compromise as CSV")
    ap.add_argument("--top", type=int, default=15, help="rows per table (default 15)")
    args = ap.parse_args(argv)

    try:
        s = run(args.pcap)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    md = to_markdown(s, args.top)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(md)
    else:
        sys.stdout.write(md)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(s, fh, indent=2)
    if args.iocs:
        with open(args.iocs, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["type", "value", "context", "first_frame"])
            w.writeheader()
            w.writerows(iocs(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
