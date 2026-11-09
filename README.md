# PCAP Threat Hunting Casebook

![tests](https://github.com/Kwakujunior7/pcap-threat-hunting-casebook/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![deps](https://img.shields.io/badge/dependencies-none-brightgreen)

Network forensics case studies from real-world style malware traffic, plus a zero-dependency Python tool that automates the first pass of every investigation.

I'm a graduate student in **DS 5590 Network Security** building toward a **SOC / network security analyst** role. This repo shows how I work a packet capture: I find who is on the network, who is logged in, what left the network and why it's suspicious, and then I write it up the way an incident responder would need it.

---

## Case studies

| # | Case | What I found | Key skills |
|---|---|---|---|
| 01 | [**Sunnystation** (2022-02-23)](cases/01-sunnystation-2022-02-23/) | Mapped 3 workstations, 2 users, the DC and a file server in an AD domain. Found a **raw-IP HTTP download with no User-Agent** (`/Ocklqc.jpg`) from the victim workstation. | Kerberos, SMB2, LDAP, DNS dynamic update, LLMNR, HTTP analysis, timeline, IOCs, ATT&CK |
| 02 | [**Wiresharkworkshop** (2024-07-30)](cases/02-wiresharkworkshop-2024-07-30/) | Identified the victim's hostname, IP, MAC, account **and full name**. Flagged an **IP-geolocation lookup** (`ip-api.com/json/`) that is typical of infostealers. | NBNS, Kerberos CNameString, LDAP user lookup, web-traffic filtering |

Each case has a summary, an asset table, a step-by-step walkthrough with my Wireshark screenshots, a timeline, defanged IOCs, a MITRE ATT&CK mapping, recommendations, and the open leads I'd chase next.

## The tool: `pcap_triage.py`

After doing these investigations by hand, I automated the questions I ask every time:

```bash
python tools/pcap_triage.py capture.pcap -o triage.md --iocs iocs.csv --json triage.json
```

| It finds | From |
|---|---|
| Internal hosts: IP ↔ MAC ↔ hostname | Ethernet, NBNS registrations, DNS dynamic updates, DHCP option 12 |
| User and machine accounts per host | Kerberos AS-REQ / TGS-REQ / AS-REP / TGS-REP `cname` (minimal ASN.1/DER parser) |
| Domain controllers | Hosts serving both Kerberos (88) and LDAP (389) |
| Suspicious HTTP | Raw-IP `Host`, missing `User-Agent`, IP-geolocation services, executable/script downloads |
| Outbound activity | External TCP SYNs, TLS SNI server names, DNS queries |
| IOCs | CSV of flagged IPs, URLs and domains, ready for a blocklist or SIEM lookup |

* **No dependencies:** pure Python standard library, so there's no Wireshark/tshark install. It reads `.pcap` and `.pcapng` files.
* **Tested in CI:** unit tests run against a [synthetic capture](tests/make_sample_pcap.py) that reproduces the patterns from my cases using documentation-only IP ranges, so **no real malware traffic is stored in this repo**.
* Sample output: [`docs/sample-triage-report.md`](docs/sample-triage-report.md)

```bash
python -m unittest discover -s tests -v
```

## Playbooks
* [PCAP investigation playbook](playbooks/pcap-investigation-playbook.md): my 6-step process from prep to report
* [Wireshark filter cheat sheet](playbooks/wireshark-filters.md): every filter used in these cases and what it answers

## Skills demonstrated
`Wireshark` · `Network forensics` · `Active Directory protocols (Kerberos, LDAP, SMB2, DNS, NBNS, LLMNR)` · `Threat hunting` · `IOC extraction` · `MITRE ATT&CK` · `Incident reporting` · `Python` · `Binary protocol parsing` · `Unit testing / GitHub Actions`

## Safety & data handling
* The PCAPs come from public training exercises at [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/). They are **not** redistributed here. Download them from the source if you want to reproduce my analysis.
* Malicious URLs and IPs in the reports are **defanged** (`hxxp://`, `[.]`).
* Anything extracted from a capture should be handled only inside an isolated VM.

## Roadmap
- [ ] Run `pcap_triage.py` against both case PCAPs and add the output to each case
- [ ] Case 03: a beaconing / C2 traffic exercise
- [ ] Add beacon-interval detection (regular connection timing) to the tool
- [ ] Export findings as Suricata / Sigma detection rules

---
**Author:** Junior Owusu Ansah · Network Security (DS 5590), New Mexico Highlands University
