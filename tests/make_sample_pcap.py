#!/usr/bin/env python3
"""
Build a small SYNTHETIC pcap that mimics the patterns from my case studies
(Windows client on an AD domain, Kerberos logon, a raw-IP HTTP download with
no User-Agent, an IP-geolocation lookup, TLS, DHCP, NBNS, DNS dynamic update).

All addresses use private / documentation ranges (RFC 1918, RFC 5737).
No real traffic or malware is involved - this exists so the triage tool can be
tested in CI without committing real malware PCAPs to GitHub.
"""

import struct
import sys

CLIENT_MAC = bytes.fromhex("aabbcc000001")
DC_MAC = bytes.fromhex("aabbcc0000dc")
GW_MAC = bytes.fromhex("aabbcc0000fe")
CLIENT, DC, GW = "10.0.0.50", "10.0.0.10", "10.0.0.1"
EVIL_IP, GEO_IP, TLS_IP = "203.0.113.66", "198.51.100.20", "198.51.100.44"


def ip_b(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ipv4(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, ip_b(src), ip_b(dst))
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def eth(src_mac, dst_mac, ip_packet):
    return dst_mac + src_mac + b"\x08\x00" + ip_packet


def udp(src, dst, sport, dport, data, smac, dmac):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    return eth(smac, dmac, ipv4(src, dst, 17, seg))


def tcp(src, dst, sport, dport, flags, data, smac, dmac, seq=1000, ack=0):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + data
    return eth(smac, dmac, ipv4(src, dst, 6, seg))


# ---- DNS / NBNS / DHCP builders ------------------------------------------- #

def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_query(name, qtype=1, tid=0x1111):
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_dynamic_update(zone, host_fqdn, ip):
    # opcode 5 (UPDATE); zone section (1), prereq (0), update (1), additional (0)
    hdr = struct.pack("!HHHHHH", 0x2222, 5 << 11, 1, 0, 1, 0)
    z = dns_name(zone) + struct.pack("!HH", 6, 1)  # SOA, IN
    rr = dns_name(host_fqdn) + struct.pack("!HHIH", 1, 1, 1200, 4) + ip_b(ip)
    return hdr + z + rr


def nb_encode(name: str, suffix: int) -> bytes:
    raw = name.upper().ljust(15)[:15].encode() + bytes([suffix])
    enc = "".join(chr((b >> 4) + 65) + chr((b & 0xF) + 65) for b in raw)
    return bytes([32]) + enc.encode() + b"\0"


def nbns_registration(name, ip):
    hdr = struct.pack("!HHHHHH", 0x3333, (5 << 11) | 0x0110, 1, 0, 0, 1)
    q = nb_encode(name, 0x00) + struct.pack("!HH", 0x20, 1)
    ar = b"\xc0\x0c" + struct.pack("!HHIHH", 0x20, 1, 300000, 6, 0) + ip_b(ip)
    return hdr + q + ar


def dhcp_request(mac, hostname, requested_ip):
    bootp = struct.pack("!BBBBIHH4s4s4s4s", 1, 1, 6, 0, 0xDEADBEEF, 0, 0, b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4)
    bootp += mac + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63"
    opts = b"\x35\x01\x03" + b"\x32\x04" + ip_b(requested_ip)
    opts += bytes([12, len(hostname)]) + hostname.encode() + b"\xff"
    return bootp + opts


# ---- Kerberos AS-REQ (DER) ------------------------------------------------ #

def der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


def ctx(n, content):
    return der(0xA0 | n, content)


def kint(v):
    return der(0x02, bytes([v]))


def kstr(s):
    return der(0x1B, s.encode())  # GeneralString


def principal(name_type, *parts):
    return der(0x30, ctx(0, kint(name_type)) + ctx(1, der(0x30, b"".join(kstr(p) for p in parts))))


def as_req(user, realm):
    body = der(0x30,
               ctx(0, der(0x03, b"\x00\x40\x81\x00\x10")) +
               ctx(1, principal(1, user)) +
               ctx(2, kstr(realm)) +
               ctx(3, principal(2, "krbtgt", realm)) +
               ctx(5, der(0x18, b"20370913024805Z")) +
               ctx(7, kint(42)) +
               ctx(8, der(0x30, kint(18))))
    req = der(0x30, ctx(1, kint(5)) + ctx(2, kint(10)) + ctx(4, body))
    msg = der(0x6A, req)
    return struct.pack("!I", len(msg)) + msg  # TCP record-mark


# ---- TLS ClientHello with SNI --------------------------------------------- #

def client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    exts = sni_ext
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


# ---- Assemble ------------------------------------------------------------- #

def build() -> list[bytes]:
    c, d, g = CLIENT_MAC, DC_MAC, GW_MAC
    frames = [
        udp("0.0.0.0", "255.255.255.255", 68, 67, dhcp_request(c, "DESKTOP-LAB01", CLIENT), c, b"\xff" * 6),
        udp(CLIENT, "10.0.0.255", 137, 137, nbns_registration("DESKTOP-LAB01", CLIENT), c, b"\xff" * 6),
        udp(CLIENT, DC, 53000, 53, dns_query("_ldap._tcp.dc._msdcs.lab.example", 33), c, d),
        udp(CLIENT, DC, 53001, 53, dns_dynamic_update("lab.example", "DESKTOP-LAB01.lab.example", CLIENT), c, d),
        tcp(CLIENT, DC, 49700, 88, 0x18, as_req("alice.smith", "LAB.EXAMPLE"), c, d),
        tcp(CLIENT, DC, 49701, 88, 0x18, as_req("DESKTOP-LAB01$", "LAB.EXAMPLE"), c, d),
        tcp(CLIENT, DC, 49702, 389, 0x02, b"", c, d),
        udp(CLIENT, DC, 53002, 53, dns_query("www.example.com"), c, d),
        # Suspicious: raw-IP host, no User-Agent, random-looking .jpg (mirrors case 01)
        tcp(CLIENT, EVIL_IP, 49200, 80, 0x02, b"", c, g),
        tcp(CLIENT, EVIL_IP, 49200, 80, 0x18,
            f"GET /Xkqzpl.jpg HTTP/1.1\r\nHost: {EVIL_IP}\r\nConnection: Keep-Alive\r\n\r\n".encode(), c, g),
        # Suspicious: IP geolocation lookup (mirrors case 02)
        tcp(CLIENT, GEO_IP, 49755, 80, 0x02, b"", c, g),
        tcp(CLIENT, GEO_IP, 49755, 80, 0x18,
            b"GET /json/ HTTP/1.1\r\nHost: ip-api.com\r\nConnection: Keep-Alive\r\n\r\n", c, g),
        # Benign: normal browser-style request
        tcp(CLIENT, "198.51.100.80", 49800, 80, 0x18,
            b"GET /connecttest.txt HTTP/1.1\r\nHost: www.msftconnecttest.com\r\nUser-Agent: Microsoft NCSI\r\n\r\n", c, g),
        tcp(CLIENT, TLS_IP, 49900, 443, 0x02, b"", c, g),
        tcp(CLIENT, TLS_IP, 49900, 443, 0x18, client_hello("assets.example.net"), c, g),
    ]
    return frames


def write_pcap(path: str) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        t = 1_700_000_000
        for i, f in enumerate(build()):
            fh.write(struct.pack("<IIII", t + i, 0, len(f), len(f)))
            fh.write(f)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    write_pcap(out)
    print(f"wrote {out}")
