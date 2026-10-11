"""Pytest configuration and synthetic fixtures for NetScope testing."""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from netscope.config import DetectionConfig
from netscope.models import PacketRecord


@pytest.fixture
def sample_detection_config() -> DetectionConfig:
    """Fixture providing a default valid DetectionConfig."""
    return DetectionConfig()


@pytest.fixture
def temp_pcap_path(tmp_path: Path) -> Path:
    """Fixture providing a temporary PCAP file path."""
    return tmp_path / "test_capture.pcap"


@pytest.fixture
def synthetic_packets_list() -> List[PacketRecord]:
    """Fixture providing an in-memory list of deterministic PacketRecords."""
    base_ts = 1700000000.0
    records = []

    # 1. TCP Handshake from 192.168.1.10:50000 to 192.168.1.20:80
    records.append(
        PacketRecord.create(
            index=1,
            timestamp=base_ts + 0.1,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            protocol="TCP",
            src_port=50000,
            dst_port=80,
            length=60,
            wire_length=60,
            tcp_flags="S",
        )
    )
    records.append(
        PacketRecord.create(
            index=2,
            timestamp=base_ts + 0.2,
            src_ip="192.168.1.20",
            dst_ip="192.168.1.10",
            protocol="TCP",
            src_port=80,
            dst_port=50000,
            length=60,
            wire_length=60,
            tcp_flags="SA",
        )
    )
    records.append(
        PacketRecord.create(
            index=3,
            timestamp=base_ts + 0.3,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            protocol="TCP",
            src_port=50000,
            dst_port=80,
            length=54,
            wire_length=54,
            tcp_flags="A",
        )
    )

    # 2. UDP DNS lookup from 192.168.1.10:52000 to 192.168.1.1:53
    records.append(
        PacketRecord.create(
            index=4,
            timestamp=base_ts + 0.5,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            protocol="UDP",
            src_port=52000,
            dst_port=53,
            length=75,
            wire_length=75,
            dns_query="example.org",
            dns_qtype="A",
        )
    )

    # 3. ICMP Echo from 192.168.1.10 to 8.8.8.8 (no ports!)
    records.append(
        PacketRecord.create(
            index=5,
            timestamp=base_ts + 1.0,
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            protocol="ICMP",
            src_port=None,
            dst_port=None,
            length=84,
            wire_length=84,
        )
    )

    return records


@pytest.fixture
def minimal_pcap_file(tmp_path: Path) -> Path:
    """Fixture creating a small valid PCAP file with 3 packets."""
    pcap_path = tmp_path / "minimal.pcap"
    base_ts = 1700000000.0

    p1 = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="S")
    )
    p1.time = base_ts

    p2 = (
        Ether()
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=12345, flags="SA")
    )
    p2.time = base_ts + 0.05

    p3 = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=12345, dport=80, flags="A")
    )
    p3.time = base_ts + 0.1

    wrpcap(str(pcap_path), [p1, p2, p3])
    return pcap_path
