"""Unit tests for NetScope packet parser module."""

from pathlib import Path
import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from netscope.exceptions import InvalidCaptureError
from netscope.parser import parse_capture, stream_packets, validate_capture_file


def test_validate_nonexistent_file(tmp_path: Path):
    """Test that missing capture file raises InvalidCaptureError."""
    missing = tmp_path / "does_not_exist.pcap"
    with pytest.raises(InvalidCaptureError, match="does not exist"):
        validate_capture_file(missing)


def test_validate_empty_file(tmp_path: Path):
    """Test that 0-byte capture file raises InvalidCaptureError."""
    empty = tmp_path / "empty.pcap"
    empty.touch()
    with pytest.raises(InvalidCaptureError, match="empty"):
        validate_capture_file(empty)


def test_parse_ipv4_tcp_packet(tmp_path: Path):
    """Test accurate extraction of IPv4 TCP packet metadata."""
    pcap = tmp_path / "tcp.pcap"
    pkt = (
        Ether()
        / IP(src="192.168.1.50", dst="10.0.0.1")
        / TCP(sport=54321, dport=443, flags="SA")
    )
    pkt.time = 1700000000.5
    wrpcap(str(pcap), [pkt])

    records, metrics = parse_capture(pcap)
    assert len(records) == 1
    assert metrics.total_read == 1
    assert metrics.parsed_ok == 1

    rec = records[0]
    assert rec.index == 1
    assert rec.src_ip == "192.168.1.50"
    assert rec.dst_ip == "10.0.0.1"
    assert rec.protocol == "TCP"
    assert rec.src_port == 54321
    assert rec.dst_port == 443
    assert rec.tcp_flags == "SA"
    assert rec.timestamp == pytest.approx(1700000000.5)
    assert rec.length > 0
    assert rec.wire_length >= rec.length
    assert rec.parsing_status == "OK"


def test_parse_ipv6_udp_packet(tmp_path: Path):
    """Test accurate extraction of IPv6 UDP packet metadata."""
    pcap = tmp_path / "ipv6_udp.pcap"
    pkt = (
        Ether(src="00:11:22:33:44:01", dst="00:11:22:33:44:fe")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / UDP(sport=1234, dport=5678)
    )
    pkt.time = 1700000001.0
    wrpcap(str(pcap), [pkt])

    records, metrics = parse_capture(pcap)
    assert len(records) == 1
    rec = records[0]
    assert rec.src_ip == "2001:db8::1"
    assert rec.dst_ip == "2001:db8::2"
    assert rec.protocol == "UDP"
    assert rec.src_port == 1234
    assert rec.dst_port == 5678
    assert rec.tcp_flags is None


def test_icmp_no_transport_ports(tmp_path: Path):
    """Test that ICMP packets do not assign transport ports."""
    pcap = tmp_path / "icmp.pcap"
    pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="8.8.4.4")
        / ICMP(type=8, code=0)
    )
    pkt.time = 1700000002.0
    wrpcap(str(pcap), [pkt])

    records, _ = parse_capture(pcap)
    assert len(records) == 1
    rec = records[0]
    assert rec.protocol == "ICMP"
    assert rec.src_ip == "192.168.1.10"
    assert rec.dst_ip == "8.8.4.4"
    assert rec.src_port is None
    assert rec.dst_port is None


def test_dns_metadata_extraction(tmp_path: Path):
    """Test DNS query name and query type extraction."""
    pcap = tmp_path / "dns.pcap"
    pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="1.1.1.1")
        / UDP(sport=43210, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="test.cloudflare.com", qtype="A"))
    )
    pkt.time = 1700000003.0
    wrpcap(str(pcap), [pkt])

    records, _ = parse_capture(pcap)
    assert len(records) == 1
    rec = records[0]
    assert rec.dns_query == "test.cloudflare.com"
    assert rec.dns_qtype == "A"


def test_streaming_safety_limit(tmp_path: Path):
    """Test that max_packets limits the stream without throwing."""
    pcap = tmp_path / "multi.pcap"
    pkts = []
    for i in range(10):
        p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1000 + i, dport=2000)
        p.time = 1700000000.0 + i
        pkts.append(p)
    wrpcap(str(pcap), pkts)

    records, metrics = parse_capture(pcap, max_packets=5)
    assert len(records) == 5
    assert metrics.truncated_by_limit is True
    assert "safety limit" in metrics.warning_message
