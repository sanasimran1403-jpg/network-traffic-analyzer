#  Network Traffic Analyzer

A Python-based PCAP threat analysis tool that detects port scans, ARP spoofing, suspicious DNS queries, ICMP floods, and possible data exfiltration — and generates a branded, dashboard-style PDF threat report.

---

##  Overview

This tool ingests a `.pcap` / `.pcapng` capture and runs it through five independent threat detectors, then produces:

- A colour-coded terminal summary
- An optional JSON export of raw findings (for SIEM/automation integration)
- A polished, dark-themed **PDF Threat Intelligence Report** with an overall risk banner, packet statistics, top talkers, per-finding evidence, and remediation recommendations

It was built and validated as part of a self-directed cybersecurity project roadmap, using a home lab (VirtualBox: Kali Linux attacker + Windows Server 2019 Domain Controller) to generate real attack traffic rather than relying on synthetic/sample captures alone.

---

##  Detection Capabilities

| Detector | What it catches | Severity |
|---|---|---|
| **Port Scan** | Vertical scans (many ports, one host) and horizontal scans (many hosts) | MEDIUM / HIGH |
| **ARP Spoofing** | Same IP address claimed by multiple MAC addresses (default: 2+ MACs) | CRITICAL |
| **Suspicious DNS** | Queries matching known malicious/C2-style TLDs and keyword patterns | MEDIUM |
| **ICMP Flood** | Excessive ICMP traffic from a single source (possible DoS) | HIGH |
| **Large Data Transfer** | Any single host sending >10MB — possible exfiltration | MEDIUM |

All thresholds are configurable constants at the top of `analyzer.py`.

---

##  Validation — Tested Against Real Attack Traffic

Rather than only testing on a sample capture, this tool was validated against live attacks generated from a Kali Linux VM against a Windows Server 2019 Domain Controller in an isolated host-only lab network.

### Test 1 — Nmap Port Scan
```bash
nmap -p 1-1000 -T4 <target-ip>
```
**Result:** ✅ Detected — `HIGH` severity, 1000 unique ports scanned from the attacker host against the DC, SYN count logged, all 1000 target ports listed in the report.

### Test 2 — ARP Spoofing (arpspoof)
```bash
arpspoof -i eth0 -t <target-ip> <gateway-ip>
```
**Result:** ✅ Detected — `CRITICAL` severity, the gateway IP flagged as claimed by 2 different MAC addresses (the attacker's spoofed MAC and the legitimate gateway MAC).

Both tests confirm the detectors correctly flag real, live attack traffic rather than only pattern-matching on synthetic data.

---

##  Sample Report Output

The PDF report includes:
- An overall risk banner (`CRITICAL` / `HIGH` / `MEDIUM` / `CLEAN`) based on the highest-severity finding
- Findings summary and packet statistics tables
- Top source IP breakdown
- Per-finding evidence cards with severity-colour coding
- A recommendations section mapped to each detector
- A branded watermark and consistent header/footer across all pages

*(See `/samples` in this repo for the full PDF reports generated during validation testing.)*

---

##  Installation

```bash
git clone https://github.com/sanasimran1403-jpg/network-traffic-analyzer.git
cd network-traffic-analyzer
pip install -r requirements.txt
```

**Requirements:** Python 3.9+, and:
```
scapy
fpdf2
requests
```

---

##  Usage

```bash
python analyzer.py <path-to-pcap> -o report.pdf -j
```

| Flag | Description |
|---|---|
| `-o`, `--output` | Output PDF path (default: `report.pdf`) |
| `-j`, `--json` | Also export findings as JSON |
| `-v`, `--vt` | Cross-check top offending IPs against VirusTotal (requires API key in `VIRUSTOTAL_API` constant) |

### Example
```bash
python analyzer.py capture.pcap -o report.pdf -j
```

---

##  Project Structure

```
network-traffic-analyzer/
├── analyzer.py              # main tool
├── requirements.txt
├── LICENSE
├── samples/
│   ├── portscan_attack.pcap         # real nmap scan capture
│   ├── arpspoof_attack.pcap         # real arpspoof capture
│   ├── portscan_report.pdf
│   └── arpspoof_report.pdf
└── README.md
```

> **Note:** The PDF report includes a subtle branded watermark. The watermark image itself (`watermark_logo.png`) is kept locally and is **not committed to this repo**. `analyzer.py` checks for its presence at runtime — if the file isn't found, the report simply generates without the watermark, no error thrown.

---

##  Known Limitations

- Uses `scapy.rdpcap()`, which loads the entire capture into memory — very large captures (500MB+) may be slow. A streaming approach via `PcapReader` would be a natural next improvement.
- ARP spoofing detection requires 2+ distinct MACs claiming the same IP within the capture window; extremely short captures of an active spoof may need a longer capture duration to catch both the spoofed and legitimate MAC.
- VirusTotal integration is optional and requires a free API key.

---

##  License

MIT License — see `LICENSE` file.

---

## Author

**Sana Simran**

- GitHub: [@sanasimran1403-jpg](https://github.com/sanasimran1403-jpg)

*Disclaimer: All attack traffic was generated and tested in an isolated local lab environment for educational purposes. Never run scanning or spoofing tools against networks or systems you do not own or have explicit permission to test.*