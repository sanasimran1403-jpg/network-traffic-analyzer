"""
Network Traffic Analyzer
========================
Author  : Sana Simran
Project : #3 — Cybersecurity Portfolio
GitHub  : github.com/sanasimran1403-jpg
Desc    : Analyzes PCAP files to detect port scans, ARP spoofing,
          suspicious DNS queries, and generates a PDF threat report
          styled like an S&S Threat Intelligence Dashboard.
"""

import sys
import os
import json
import argparse
from fpdf.enums import XPos, YPos
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ARP, DNS, DNSQR, ICMP
except ImportError:
    print("[!] scapy not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from fpdf import FPDF
except ImportError:
    print("[!] fpdf2 not installed. Run: pip install fpdf2")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] requests not installed. Run: pip install requests")
    sys.exit(1)


# ══════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════

PORT_SCAN_THRESHOLD   = 15    # unique ports from one IP = port scan
ARP_SPOOF_THRESHOLD   = 2     # same IP claimed by multiple MACs
DNS_SUSPICIOUS = {            # known malicious / C2-like TLDs & keywords
    ".onion", ".bit", ".coin", ".bazar", "update-", "security-",
    "microsoft-", "google-update", "cdn-", "analytics-",
}
VIRUSTOTAL_API = ""           # optional — paste your free VT API key here
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WATERMARK_PATH = os.path.join(_SCRIPT_DIR, "watermark_logo.png")


# ══════════════════════════════════════════════════════
#  COLOURS (terminal)
# ══════════════════════════════════════════════════════
R = "\033[91m"   # red
Y = "\033[93m"   # yellow
G = "\033[92m"   # green
C = "\033[96m"   # cyan
W = "\033[0m"    # reset
B = "\033[1m"    # bold


# ══════════════════════════════════════════════════════
#  PDF THEME (S&S Threat Intel Dashboard style)
# ══════════════════════════════════════════════════════

BG_DARK      = (10, 13, 20)     # page background
BAR_DARK     = (17, 21, 31)     # top/section bars
CARD_BG      = (19, 23, 33)     # table row (even)
CARD_BG_ALT  = (25, 30, 42)     # table row (odd)
BORDER_GRAY  = (42, 49, 64)
TEXT_WHITE   = (232, 236, 245)
TEXT_GRAY    = (145, 154, 173)
ACCENT_TEAL  = (56, 189, 178)

SEVERITY_COLOR = {
    "CRITICAL": (220, 53, 69),
    "HIGH"    : (255, 140, 40),
    "MEDIUM"  : (230, 180, 40),
    "LOW"     : (60, 180, 100),
    "CLEAN"   : (56, 189, 178),
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# ══════════════════════════════════════════════════════
#  PCAP LOADER
# ══════════════════════════════════════════════════════

def load_pcap(path: str):
    if not os.path.exists(path):
        print(f"{R}[!] File not found: {path}{W}")
        sys.exit(1)
    print(f"{C}[*] Loading PCAP: {path}{W}")
    packets = rdpcap(path)
    print(f"{G}[+] Loaded {len(packets)} packets{W}")
    return packets


# ══════════════════════════════════════════════════════
#  DETECTORS
# ══════════════════════════════════════════════════════

def detect_port_scan(packets):
    """Detect horizontal and vertical port scans."""
    findings = []
    src_ports   = defaultdict(set)   # src_ip → set of dst_ports
    src_targets = defaultdict(set)   # src_ip → set of dst_ips  (horizontal)
    syn_counts  = defaultdict(int)

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags

            src_ports[src].add(dport)
            src_targets[src].add(dst)

            if flags == 0x02:          # SYN only
                syn_counts[src] += 1

    for ip, ports in src_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            severity = "HIGH" if len(ports) > 50 else "MEDIUM"
            findings.append({
                "type"    : "Port Scan",
                "severity": severity,
                "src_ip"  : ip,
                "detail"  : f"Scanned {len(ports)} unique ports "
                            f"(SYN count: {syn_counts[ip]})",
                "ports"   : sorted(list(ports))[:20],
            })

    for ip, targets in src_targets.items():
        if len(targets) >= PORT_SCAN_THRESHOLD:
            findings.append({
                "type"    : "Horizontal Scan",
                "severity": "HIGH",
                "src_ip"  : ip,
                "detail"  : f"Contacted {len(targets)} unique hosts - "
                            f"possible network sweep",
                "ports"   : [],
            })

    return findings


def detect_arp_spoofing(packets):
    """Detect ARP spoofing: same IP announced by multiple MACs."""
    findings = []
    ip_mac_map = defaultdict(set)   # ip → set of MACs

    for pkt in packets:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:   # ARP reply
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            ip_mac_map[ip].add(mac)

    for ip, macs in ip_mac_map.items():
        if len(macs) >= ARP_SPOOF_THRESHOLD:
            findings.append({
                "type"    : "ARP Spoofing",
                "severity": "CRITICAL",
                "src_ip"  : ip,
                "detail"  : f"IP {ip} claimed by {len(macs)} different MACs: "
                            f"{', '.join(macs)}",
                "ports"   : [],
            })

    return findings


def detect_suspicious_dns(packets):
    """Detect suspicious or potentially malicious DNS queries."""
    findings = []
    seen = set()

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                continue

            if qname in seen:
                continue
            seen.add(qname)

            for pattern in DNS_SUSPICIOUS:
                if pattern in qname.lower():
                    src = pkt[IP].src if pkt.haslayer(IP) else "unknown"
                    findings.append({
                        "type"    : "Suspicious DNS",
                        "severity": "MEDIUM",
                        "src_ip"  : src,
                        "detail"  : f"Suspicious query: {qname} "
                                    f"(matched pattern: '{pattern}')",
                        "ports"   : [],
                    })
                    break

    return findings


def detect_icmp_flood(packets):
    """Detect ICMP flood (possible DoS)."""
    findings = []
    icmp_count = defaultdict(int)

    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            icmp_count[pkt[IP].src] += 1

    for ip, count in icmp_count.items():
        if count > 100:
            findings.append({
                "type"    : "ICMP Flood",
                "severity": "HIGH",
                "src_ip"  : ip,
                "detail"  : f"Sent {count} ICMP packets — possible DoS",
                "ports"   : [],
            })

    return findings


def detect_large_transfers(packets):
    """Detect unusually large data transfers (possible exfiltration)."""
    findings = []
    byte_totals = defaultdict(int)

    for pkt in packets:
        if pkt.haslayer(IP):
            byte_totals[pkt[IP].src] += len(pkt)

    for ip, total in byte_totals.items():
        if total > 10_000_000:   # 10 MB threshold
            findings.append({
                "type"    : "Large Transfer",
                "severity": "MEDIUM",
                "src_ip"  : ip,
                "detail"  : f"Sent {total / 1_000_000:.2f} MB - "
                            f"possible data exfiltration",
                "ports"   : [],
            })

    return findings


# ══════════════════════════════════════════════════════
#  VIRUSTOTAL (optional)
# ══════════════════════════════════════════════════════

def vt_check_ip(ip: str) -> str:
    if not VIRUSTOTAL_API:
        return "VT API key not configured"
    try:
        url  = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        hdrs = {"x-apikey": VIRUSTOTAL_API}
        r    = requests.get(url, headers=hdrs, timeout=5)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            mal   = stats.get("malicious", 0)
            sus   = stats.get("suspicious", 0)
            return f"Malicious: {mal} | Suspicious: {sus}"
        return f"VT status: {r.status_code}"
    except Exception as e:
        return f"VT error: {e}"


# ══════════════════════════════════════════════════════
#  STATS
# ══════════════════════════════════════════════════════

def collect_stats(packets):
    stats = {
        "total"   : len(packets),
        "tcp"     : 0,
        "udp"     : 0,
        "icmp"    : 0,
        "arp"     : 0,
        "dns"     : 0,
        "other"   : 0,
        "top_src" : defaultdict(int),
        "top_dst" : defaultdict(int),
    }
    for pkt in packets:
        if pkt.haslayer(TCP):   stats["tcp"]  += 1
        elif pkt.haslayer(UDP): stats["udp"]  += 1
        elif pkt.haslayer(ICMP):stats["icmp"] += 1
        elif pkt.haslayer(ARP): stats["arp"]  += 1
        else:                   stats["other"]+= 1
        if pkt.haslayer(DNS):   stats["dns"]  += 1
        if pkt.haslayer(IP):
            stats["top_src"][pkt[IP].src] += 1
            stats["top_dst"][pkt[IP].dst] += 1
    return stats


# ══════════════════════════════════════════════════════
#  PDF REPORT — S&S Threat Intel Dashboard theme
# ══════════════════════════════════════════════════════

class ReportPDF(FPDF):
    def header(self):
        # full-page dark background (redrawn on every page)
        self.set_fill_color(*BG_DARK)
        self.rect(0, 0, 210, 297, "F")

        # large faint watermark logo, centered on the page
        if os.path.exists(WATERMARK_PATH):
            wm_w = 140
            wm_h = wm_w * 386 / 564   # preserve aspect ratio (564x386 source)
            wm_x = (210 - wm_w) / 2
            wm_y = (297 - wm_h) / 2
            self.image(WATERMARK_PATH, x=wm_x, y=wm_y, w=wm_w, h=wm_h)

        # top bar
        self.set_fill_color(*BAR_DARK)
        self.rect(0, 0, 210, 24, "F")

        text_x = 10

        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*TEXT_WHITE)
        self.set_xy(text_x, 5)
        self.cell(0, 6, "S&S  |  Network Traffic Analyzer")

        self.set_font("Helvetica", "", 8)
        self.set_text_color(*TEXT_GRAY)
        self.set_xy(text_x, 12)
        self.cell(0, 5, "Threat Intelligence Report")

        self.set_font("Helvetica", "", 8)
        self.set_text_color(*TEXT_GRAY)
        self.set_xy(0, 9)
        self.cell(200, 5, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", align="R")

        self.set_draw_color(*ACCENT_TEAL)
        self.set_line_width(0.6)
        self.line(0, 24, 210, 24)
        self.set_line_width(0.2)
        self.set_xy(10, 30)

    def footer(self):
        self.set_y(-16)
        self.set_draw_color(*BORDER_GRAY)
        self.set_line_width(0.2)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*TEXT_GRAY)
        self.set_xy(10, self.get_y() + 3)
        self.cell(100, 8, "S&S  |  Network Traffic Analyzer")
        self.set_xy(100, self.get_y())
        self.cell(90, 8, f"Page {self.page_no()}", align="R")


def section_header(pdf, title):
    """Small teal square + bold section title, like '■ VirusTotal Analysis'."""
    y = pdf.get_y()
    pdf.set_fill_color(*ACCENT_TEAL)
    pdf.rect(10, y + 1.5, 3.5, 3.5, "F")
    pdf.set_xy(16, y)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*TEXT_WHITE)
    pdf.cell(0, 7, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)


def draw_kv_table(pdf, rows, x=10, w=190, col1_ratio=0.42, row_h=8):
    """Two-column dark key/value table (VirusTotal / AlienVault OTX style)."""
    col1_w = w * col1_ratio
    col2_w = w - col1_w
    y = pdf.get_y()
    for i, (k, v) in enumerate(rows):
        fill = CARD_BG if i % 2 == 0 else CARD_BG_ALT
        pdf.set_fill_color(*fill)
        pdf.rect(x, y, w, row_h, "F")
        pdf.set_draw_color(*BORDER_GRAY)
        pdf.rect(x, y, w, row_h)

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*TEXT_GRAY)
        pdf.set_xy(x + 4, y + 2)
        pdf.cell(col1_w - 6, row_h - 4, str(k))

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*TEXT_WHITE)
        pdf.set_xy(x + col1_w + 2, y + 2)
        pdf.cell(col2_w - 6, row_h - 4, str(v))

        y += row_h
    pdf.set_xy(x, y + 4)


def generate_pdf(findings, stats, pcap_path, output_path):
    pdf = ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # ── Determine overall risk level
    present = {f["severity"] for f in findings}
    overall = next((s for s in SEVERITY_ORDER if s in present), "CLEAN")
    risk_color = SEVERITY_COLOR[overall]

    total_f  = len(findings)
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in findings if f["severity"] == "HIGH")
    medium   = sum(1 for f in findings if f["severity"] == "MEDIUM")

    # ── Risk banner (bordered box, like the CRITICAL/CLEAN box in sample)
    box_y = pdf.get_y()
    pdf.set_fill_color(*BAR_DARK)
    pdf.set_draw_color(*risk_color)
    pdf.set_line_width(0.8)
    pdf.rect(10, box_y, 190, 30, "FD")
    pdf.set_line_width(0.2)

    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*risk_color)
    pdf.set_xy(10, box_y + 6)
    pdf.cell(190, 12, overall, align="C")

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*TEXT_GRAY)
    pdf.set_xy(10, box_y + 20)
    pdf.cell(190, 6, f"PCAP: {os.path.basename(pcap_path)}   |   Findings: {total_f}", align="C")
    pdf.set_y(box_y + 36)

    # ── Findings summary table
    section_header(pdf, "Findings Summary")
    draw_kv_table(pdf, [
        ("Total Findings", total_f),
        ("Critical",       critical),
        ("High",           high),
        ("Medium",         medium),
    ])
    pdf.ln(4)

    # ── Packet statistics table
    section_header(pdf, "Packet Statistics")
    draw_kv_table(pdf, [
        ("Total Packets", stats["total"]),
        ("TCP",           stats["tcp"]),
        ("UDP",           stats["udp"]),
        ("ICMP",          stats["icmp"]),
        ("ARP",           stats["arp"]),
        ("DNS Queries",   stats["dns"]),
    ])
    pdf.ln(4)

    # ── Top source IPs table
    top_src = sorted(stats["top_src"].items(), key=lambda x: x[1], reverse=True)[:5]
    if top_src:
        section_header(pdf, "Top Source IPs")
        draw_kv_table(pdf, [(ip, f"{count} packets") for ip, count in top_src])
        pdf.ln(4)

    # ── Threat Findings
    pdf.add_page()
    section_header(pdf, f"Threat Findings ({total_f})")

    if not findings:
        pdf.set_fill_color(*CARD_BG)
        pdf.set_draw_color(*BORDER_GRAY)
        pdf.rect(10, pdf.get_y(), 190, 12, "FD")
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(*SEVERITY_COLOR["CLEAN"])
        pdf.set_xy(14, pdf.get_y() + 3)
        pdf.cell(0, 6, "No threats detected in this PCAP.")
        pdf.ln(18)
    else:
        for i, f in enumerate(findings, 1):
            color = SEVERITY_COLOR.get(f["severity"], (100, 100, 100))
            card_y = pdf.get_y()
            card_h = 22 if not f.get("ports") else 28

            # card background + left accent bar (severity colour)
            pdf.set_fill_color(*CARD_BG)
            pdf.set_draw_color(*BORDER_GRAY)
            pdf.rect(10, card_y, 190, card_h, "FD")
            pdf.set_fill_color(*color)
            pdf.rect(10, card_y, 3, card_h, "F")

            # severity badge
            pdf.set_fill_color(*color)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 8)
            pdf.rect(16, card_y + 3, 22, 6, "F")
            pdf.set_xy(16, card_y + 3)
            pdf.cell(22, 6, f["severity"], align="C")

            # type + IP
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*TEXT_WHITE)
            pdf.set_xy(42, card_y + 3)
            pdf.cell(0, 6, f"#{i}  {f['type']}  -  {f['src_ip']}")

            # detail
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*TEXT_GRAY)
            pdf.set_xy(16, card_y + 11)
            pdf.multi_cell(180, 5, f["detail"])

            if f.get("ports"):
                pdf.set_font("Helvetica", "I", 8)
                pdf.set_text_color(*TEXT_GRAY)
                pdf.set_xy(16, card_y + 19)
                ports_str = ", ".join(str(p) for p in f["ports"][:20])
                if len(f["ports"]) > 20:
                    ports_str += f" ... (+{len(f['ports'])-20} more)"
                pdf.multi_cell(180, 5, f"Ports: {ports_str}")

            pdf.set_y(card_y + card_h + 4)

    # ── Recommendations
    pdf.add_page()
    section_header(pdf, "Recommendations")

    recs = [
        ("Port Scan / Horizontal Scan",
         "Implement IDS rules (Snort/Suricata) to alert on rapid port sweep activity. "
         "Consider geo-blocking and rate-limiting at the firewall level."),
        ("ARP Spoofing",
         "Enable Dynamic ARP Inspection (DAI) on managed switches. "
         "Use static ARP entries for critical hosts. Deploy ARP monitoring tools."),
        ("Suspicious DNS",
         "Deploy a DNS filtering solution (e.g., Pi-hole, Cisco Umbrella). "
         "Block queries to known malicious TLDs at the DNS resolver level."),
        ("ICMP Flood",
         "Rate-limit ICMP traffic at the firewall. "
         "Consider blocking external ICMP echo requests to internal hosts."),
        ("Large Data Transfer",
         "Implement DLP (Data Loss Prevention) policies. "
         "Alert on outbound transfers exceeding baseline thresholds."),
    ]

    for title, body in recs:
        card_y = pdf.get_y()
        pdf.set_fill_color(*CARD_BG)
        pdf.set_draw_color(*BORDER_GRAY)
        pdf.set_font("Helvetica", "", 9)
        # estimate height via multi_cell dry-run isn't trivial in fpdf2, use fixed generous height
        card_h = 22
        pdf.rect(10, card_y, 190, card_h, "FD")
        pdf.set_fill_color(*ACCENT_TEAL)
        pdf.rect(10, card_y, 3, card_h, "F")

        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*TEXT_WHITE)
        pdf.set_xy(16, card_y + 3)
        pdf.cell(0, 6, title)

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*TEXT_GRAY)
        pdf.set_xy(16, card_y + 10)
        pdf.multi_cell(180, 5, body)

        pdf.set_y(card_y + card_h + 4)

    # ── Footer signature block
    sig_y = pdf.get_y()
    pdf.set_fill_color(*BAR_DARK)
    pdf.set_draw_color(*ACCENT_TEAL)
    pdf.rect(10, sig_y, 190, 16, "FD")
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*TEXT_WHITE)
    pdf.set_xy(15, sig_y + 3)
    pdf.cell(0, 5, "Sana Simran  |  Cybersecurity Portfolio  |  github.com/sanasimran1403-jpg")
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*TEXT_GRAY)
    pdf.set_xy(15, sig_y + 9)
    pdf.cell(0, 5, "For educational and authorized security assessment purposes only.")

    pdf.output(output_path)
    print(f"{G}[+] PDF report saved: {output_path}{W}")


# ══════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer — Sana Simran Cybersecurity Portfolio",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("pcap",           help="Path to the .pcap / .pcapng file")
    parser.add_argument("-o", "--output", help="Output PDF path (default: report.pdf)",
                        default="report.pdf")
    parser.add_argument("-j", "--json",   help="Also save findings as JSON",
                        action="store_true")
    parser.add_argument("-v", "--vt",     help="Check top IPs on VirusTotal (requires API key)",
                        action="store_true")
    args = parser.parse_args()

    print(f"\n{B}{C}╔══════════════════════════════════════════╗")
    print(f"║   Network Traffic Analyzer v1.0         ║")
    print(f"║   Sana Simran — Cybersecurity Portfolio  ║")
    print(f"╚══════════════════════════════════════════╝{W}\n")

    # Load
    packets = load_pcap(args.pcap)

    # Stats
    print(f"{C}[*] Collecting packet statistics...{W}")
    stats = collect_stats(packets)

    # Detect
    print(f"{C}[*] Running threat detectors...{W}")
    findings = []
    findings += detect_port_scan(packets)
    findings += detect_arp_spoofing(packets)
    findings += detect_suspicious_dns(packets)
    findings += detect_icmp_flood(packets)
    findings += detect_large_transfers(packets)

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 5))

    # Print summary
    print(f"\n{B}{'─'*50}")
    print(f"  ANALYSIS COMPLETE")
    print(f"{'─'*50}{W}")
    print(f"  Total packets  : {stats['total']}")
    print(f"  TCP            : {stats['tcp']}")
    print(f"  UDP            : {stats['udp']}")
    print(f"  DNS queries    : {stats['dns']}")
    print(f"  Findings       : {len(findings)}")
    print(f"{'─'*50}\n")

    for f in findings:
        color = R if f["severity"] in ("CRITICAL", "HIGH") else Y
        print(f"  {color}[{f['severity']:8}]{W} {f['type']:<20} {f['src_ip']}")
        print(f"             {f['detail'][:80]}")

    # Optional VT check
    if args.vt and findings:
        print(f"\n{C}[*] VirusTotal checks...{W}")
        checked = set()
        for f in findings[:5]:
            ip = f["src_ip"]
            if ip not in checked and ip != "unknown":
                result = vt_check_ip(ip)
                print(f"  VT {ip}: {result}")
                checked.add(ip)

    # JSON export
    if args.json:
        json_path = args.output.replace(".pdf", ".json")
        with open(json_path, "w") as jf:
            json.dump({"stats": dict(stats), "findings": findings}, jf, indent=2, default=str)
        print(f"{G}[+] JSON saved: {json_path}{W}")

    # PDF
    print(f"\n{C}[*] Generating PDF report...{W}")
    generate_pdf(findings, stats, args.pcap, args.output)

    print(f"\n{G}{B}[✓] Done! Report: {args.output}{W}\n")


if __name__ == "__main__":
    main()