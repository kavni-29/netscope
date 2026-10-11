"""Integration tests verifying full end-to-end NetScope analysis pipeline."""

from pathlib import Path
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from netscope.cli import run_analysis_pipeline
from netscope.config import DetectionConfig
from netscope.reporting import (
    export_alerts_csv,
    export_flows_csv,
    export_json,
    export_markdown_report,
)


def test_end_to_end_pipeline(tmp_path: Path):
    """Verify complete pipeline produces known deterministic values and exports."""
    pcap_path = tmp_path / "integration.pcap"
    base_ts = 1700000000.0

    pkts = []
    # 1. Normal TCP flow (3 packets)
    p1 = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=50000, dport=80, flags="S")
    p1.time = base_ts + 0.1
    p2 = Ether() / IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=80, dport=50000, flags="SA")
    p2.time = base_ts + 0.2
    p3 = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=50000, dport=80, flags="A")
    p3.time = base_ts + 0.3
    pkts.extend([p1, p2, p3])

    # 2. ICMP ping (2 packets)
    p4 = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(type=8, code=0)
    p4.time = base_ts + 0.5
    p5 = Ether() / IP(src="8.8.8.8", dst="192.168.1.10") / ICMP(type=0, code=0)
    p5.time = base_ts + 0.6
    pkts.extend([p4, p5])

    # 3. DNS query (1 packet)
    p6 = Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=53000, dport=53) / DNS(qd=DNSQR(qname="test.org"))
    p6.time = base_ts + 0.8
    pkts.append(p6)

    # 4. Port scan anomaly: 10.0.0.99 contacts 12 distinct ports on 192.168.1.50
    for idx in range(12):
        ps = Ether() / IP(src="10.0.0.99", dst="192.168.1.50") / TCP(sport=40000 + idx, dport=1000 + idx, flags="S")
        ps.time = base_ts + 1.0 + (idx * 0.05)
        pkts.append(ps)

    wrpcap(str(pcap_path), pkts)

    # Total packets: 3 (TCP) + 2 (ICMP) + 1 (UDP) + 12 (TCP scan) = 18 packets
    cfg = DetectionConfig(
        port_diversity_threshold=10,  # 12 > 10 -> will trigger RULE_PORT_DIVERSITY
        port_diversity_window_sec=5.0,
    )

    summary, stats, flows, alerts = run_analysis_pipeline(pcap_path, config=cfg)

    # Assertions
    assert summary.packets_processed == 18
    assert summary.packets_skipped == 0
    assert summary.identified_flows == 15  # 1 HTTP + 1 ICMP + 1 DNS + 12 scan probe flows
    assert stats.protocols["TCP"].packet_count == 15
    assert stats.protocols["ICMP"].packet_count == 2
    assert stats.protocols["UDP"].packet_count == 1

    # Verify expected alert
    assert len(alerts) >= 1
    scan_alert = next((a for a in alerts if a.rule_id == "RULE_PORT_DIVERSITY"), None)
    assert scan_alert is not None
    assert scan_alert.endpoint == "10.0.0.99"
    assert "12 distinct ports" in scan_alert.observed_value

    # Verify exports work on integrated dataset
    out_dir = tmp_path / "integrated_reports"
    export_flows_csv(flows, out_dir / "flows.csv")
    export_alerts_csv(alerts, out_dir / "alerts.csv")
    export_json(summary, stats, flows, alerts, cfg, out_dir / "report.json")
    export_markdown_report(summary, stats, flows, alerts, cfg, out_dir / "report.md")

    assert (out_dir / "flows.csv").stat().st_size > 0
    assert (out_dir / "alerts.csv").stat().st_size > 0
    assert (out_dir / "report.json").stat().st_size > 0
    assert (out_dir / "report.md").stat().st_size > 0
