import csv
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
sys.path.insert(0, HERE)

import make_sample_pcap  # noqa: E402
import pcap_triage  # noqa: E402


class TriageOnSyntheticCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pcap = os.path.join(cls.tmp.name, "sample.pcap")
        make_sample_pcap.write_pcap(cls.pcap)
        cls.s = pcap_triage.run(cls.pcap)
        cls.hosts = {h["ip"]: h for h in cls.s["hosts"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_packet_count(self):
        self.assertEqual(self.s["packets"], len(make_sample_pcap.build()))

    def test_client_hostname_from_nbns_dns_and_dhcp(self):
        names = self.hosts["10.0.0.50"]["hostnames"]
        self.assertIn("DESKTOP-LAB01", names)                 # NBNS + DHCP option 12
        self.assertIn("DESKTOP-LAB01.lab.example", names)     # DNS dynamic update

    def test_client_mac(self):
        self.assertEqual(self.hosts["10.0.0.50"]["mac"], "aa:bb:cc:00:00:01")

    def test_kerberos_user_and_machine_account(self):
        h = self.hosts["10.0.0.50"]
        self.assertEqual(h["users"], ["alice.smith"])
        self.assertEqual(h["machine_accounts"], ["DESKTOP-LAB01$"])
        self.assertEqual(self.s["realms"], ["LAB.EXAMPLE"])

    def test_domain_controller_detected(self):
        self.assertEqual(self.s["domain_controllers"], ["10.0.0.10"])
        self.assertIn("domain controller", self.hosts["10.0.0.10"]["role"])

    def test_raw_ip_http_without_user_agent_is_flagged(self):
        r = next(x for x in self.s["http"] if x["uri"] == "/Xkqzpl.jpg")
        self.assertTrue(r["suspicious"])
        self.assertTrue(any("raw external IP" in m for m in r["reasons"]))
        self.assertTrue(any("User-Agent" in m for m in r["reasons"]))

    def test_ip_geolocation_lookup_is_flagged(self):
        r = next(x for x in self.s["http"] if x["host"] == "ip-api.com")
        self.assertTrue(any("geolocation" in m for m in r["reasons"]))

    def test_benign_request_not_flagged(self):
        r = next(x for x in self.s["http"] if x["host"] == "www.msftconnecttest.com")
        self.assertFalse(r["suspicious"])

    def test_tls_sni(self):
        self.assertEqual(self.s["tls_sni"][0]["server_name"], "assets.example.net")

    def test_external_connections(self):
        dsts = {(e["dst"], e["port"]) for e in self.s["external_tcp"]}
        self.assertIn(("203.0.113.66", 80), dsts)
        self.assertNotIn(("10.0.0.10", 389), dsts)  # internal traffic excluded

    def test_cli_outputs(self):
        md = os.path.join(self.tmp.name, "r.md")
        ioc = os.path.join(self.tmp.name, "i.csv")
        js = os.path.join(self.tmp.name, "r.json")
        self.assertEqual(pcap_triage.main([self.pcap, "-o", md, "--iocs", ioc, "--json", js]), 0)
        with open(md, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("## Internal hosts", text)
        self.assertIn("alice.smith", text)
        with open(ioc, newline="", encoding="utf-8") as fh:
            values = {row["value"] for row in csv.DictReader(fh)}
        self.assertIn("203.0.113.66", values)
        self.assertIn("http://ip-api.com/json/", values)

    def test_bad_file_returns_error(self):
        bad = os.path.join(self.tmp.name, "bad.pcap")
        with open(bad, "wb") as fh:
            fh.write(b"not a pcap at all, just text" * 2)
        self.assertEqual(pcap_triage.main([bad]), 1)


class PcapngReader(unittest.TestCase):
    def test_reads_minimal_pcapng(self):
        import struct
        frame = make_sample_pcap.build()[9]
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        shb = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body + struct.pack("<I", 12 + len(shb_body))
        idb_body = struct.pack("<HHI", 1, 0, 65535)
        idb = struct.pack("<II", 1, 12 + len(idb_body)) + idb_body + struct.pack("<I", 12 + len(idb_body))
        pad = (4 - len(frame) % 4) % 4
        epb_body = struct.pack("<IIIII", 0, 0, 1_000_000, len(frame), len(frame)) + frame + b"\0" * pad
        epb = struct.pack("<II", 6, 12 + len(epb_body)) + epb_body + struct.pack("<I", 12 + len(epb_body))
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as fh:
            fh.write(shb + idb + epb)
            path = fh.name
        try:
            s = pcap_triage.run(path)
            self.assertEqual(s["packets"], 1)
            self.assertTrue(s["http"][0]["suspicious"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
