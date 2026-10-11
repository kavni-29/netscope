"""Synthetic PCAP Generator for NetScope Demonstration.

Generates a 100% synthetic, legally clean packet capture containing normal
multi-protocol network traffic (HTTP, DNS, ICMP, IPv6) alongside controlled
synthetic anomaly patterns (Port Scanning, SYN flood probes, Volume Deviations).
"""

from __future__ import annotations

from pathlib import Path
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def generate_synthetic_capture(output_path: str | Path) -> Path:
    """Generate deterministic synthetic packet capture for demonstration and testing."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    packets = []
    base_ts = 1700000000.0  # Stable synthetic base epoch timestamp

    # 1. Normal DNS Resolution (Client -> Resolver 192.168.1.1)
    # Query: example.com
    dns_query = (
        Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe")
        / IP(src="192.168.1.105", dst="192.168.1.1")
        / UDP(sport=53120, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    dns_query.time = base_ts + 0.1
    packets.append(dns_query)

    # Response: example.com -> 93.184.216.34
    dns_resp = (
        Ether(src="00:11:22:33:44:fe", dst="00:11:22:33:44:01")
        / IP(src="192.168.1.1", dst="192.168.1.105")
        / UDP(sport=53, dport=53120)
        / DNS(
            qr=1,
            aa=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34"),
        )
    )
    dns_resp.time = base_ts + 0.12
    packets.append(dns_resp)

    # 2. Normal HTTP Transaction: 192.168.1.105 <-> 93.184.216.34:80
    # Three-way handshake
    syn_pkt = (
        Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe")
        / IP(src="192.168.1.105", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="S", seq=1000)
    )
    syn_pkt.time = base_ts + 0.2
    packets.append(syn_pkt)

    syn_ack_pkt = (
        Ether(src="00:11:22:33:44:fe", dst="00:11:22:33:44:01")
        / IP(src="93.184.216.34", dst="192.168.1.105")
        / TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001)
    )
    syn_ack_pkt.time = base_ts + 0.25
    packets.append(syn_ack_pkt)

    ack_pkt = (
        Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe")
        / IP(src="192.168.1.105", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001)
    )
    ack_pkt.time = base_ts + 0.28
    packets.append(ack_pkt)

    # HTTP GET Request
    http_req = (
        Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe")
        / IP(src="192.168.1.105", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=5001)
        / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetScope-Synthetic\r\n\r\n"
    )
    http_req.time = base_ts + 0.3
    packets.append(http_req)

    # HTTP Response Data Fragments
    for i in range(4):
        resp_data = (
            Ether(src="00:11:22:33:44:fe", dst="00:11:22:33:44:01")
            / IP(src="93.184.216.34", dst="192.168.1.105")
            / TCP(sport=80, dport=49152, flags="A", seq=5001 + (i * 1000), ack=1070)
            / (b"X" * 1000)
        )
        resp_data.time = base_ts + 0.35 + (i * 0.05)
        packets.append(resp_data)

    # Teardown
    fin_pkt = (
        Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe")
        / IP(src="192.168.1.105", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="FA", seq=1070, ack=9001)
    )
    fin_pkt.time = base_ts + 0.6
    packets.append(fin_pkt)

    # 3. Normal ICMP Echo Request / Reply
    for seq_num in range(1, 4):
        echo_req = (
            Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe")
            / IP(src="192.168.1.105", dst="8.8.8.8")
            / ICMP(type=8, code=0, id=1234, seq=seq_num)
            / (b"NETSCOPE_PING" * 4)
        )
        echo_req.time = base_ts + 1.0 + seq_num
        packets.append(echo_req)

        echo_rep = (
            Ether(src="00:11:22:33:44:fe", dst="00:11:22:33:44:01")
            / IP(src="8.8.8.8", dst="192.168.1.105")
            / ICMP(type=0, code=0, id=1234, seq=seq_num)
            / (b"NETSCOPE_PING" * 4)
        )
        echo_rep.time = base_ts + 1.05 + seq_num
        packets.append(echo_rep)

    # 4. Normal IPv6 Communication
    for i in range(3):
        v6_pkt = (
            Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe")
            / IPv6(src="2001:db8::10", dst="2001:db8::ff")
            / UDP(sport=50000 + i, dport=5353)
            / (b"MDNS_V6_TEST_" + str(i).encode())
        )
        v6_pkt.time = base_ts + 5.0 + (i * 0.2)
        packets.append(v6_pkt)

    # 5. Synthetic Anomaly Pattern A: Rapid Port Scanning Probes
    # Source 10.0.0.99 probes 22 distinct destination ports on 192.168.1.50 in 1.5 seconds
    # Triggers RULE_PORT_DIVERSITY (> 15 distinct ports)
    target_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000
    ]
    for idx, port in enumerate(target_ports):
        scan_syn = (
            Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:fe")
            / IP(src="10.0.0.99", dst="192.168.1.50")
            / TCP(sport=40000 + idx, dport=port, flags="S", seq=20000 + idx)
        )
        scan_syn.time = base_ts + 7.0 + (idx * 0.05)
        packets.append(scan_syn)

    # 6. Synthetic Anomaly Pattern B: High TCP SYN Probe Burst Without ACK
    # Source 10.0.0.77 sends 20 SYN-only packets to 192.168.1.20:443
    # Triggers RULE_SYN_WITHOUT_ACK (> 75% SYN without ACK)
    for idx in range(20):
        syn_probe = (
            Ether(src="00:de:ad:be:ef:01", dst="00:11:22:33:44:fe")
            / IP(src="10.0.0.77", dst="192.168.1.20")
            / TCP(sport=52000 + idx, dport=443, flags="S", seq=30000 + idx)
        )
        syn_probe.time = base_ts + 9.0 + (idx * 0.04)
        packets.append(syn_probe)

    # 7. Synthetic Anomaly Pattern C: High Traffic Volume Spike
    # Burst of 40 large payload packets within second 12
    # Triggers RULE_VOLUME_DEVIATION (Z-score deviation) & RULE_HIGH_PACKET_RATE
    for idx in range(60):
        burst_pkt = (
            Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe")
            / IP(src="192.168.1.105", dst="104.244.42.1")
            / TCP(sport=55000, dport=443, flags="A", seq=40000 + (idx * 1400), ack=1)
            / (b"B" * 1400)
        )
        burst_pkt.time = base_ts + 12.0 + (idx * 0.015)
        packets.append(burst_pkt)

    # Final packets to ensure proper capture duration span
    tail_pkt = (
        Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe")
        / IP(src="192.168.1.105", dst="192.168.1.1")
        / UDP(sport=53121, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="test.local", qtype="A"))
    )
    tail_pkt.time = base_ts + 14.5
    packets.append(tail_pkt)

    # Sort deterministically by timestamp before writing
    packets.sort(key=lambda p: float(p.time))

    wrpcap(str(path), packets)
    return path


if __name__ == "__main__":
    out = Path("samples") / "synthetic_demo.pcap"
    created = generate_synthetic_capture(out)
    print(f"Generated synthetic demonstration capture: {created.resolve()}")
