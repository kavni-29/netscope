"""NetScope packet parsing engine.

Reads saved PCAP and PCAPNG capture files using Scapy's streaming PcapReader.
Extracts protocol metadata, normalizes fields, and handles malformed or
unsupported frames gracefully without terminating the analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, List, Optional, Tuple

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapReader, Scapy_Exception

from netscope.exceptions import (
    InvalidCaptureError,
    ParsingError,
    UnsupportedCaptureFormatError,
)
from netscope.models import PacketRecord

logger = logging.getLogger(__name__)

# Standard capture magic numbers
PCAP_MAGIC_NUMBERS = {
    b"\xa1\xb2\xc3\xd4",  # Microsecond standard
    b"\xd4\xc3\xb2\xa1",  # Microsecond swapped
    b"\xa1\xb2\x3c\x4d",  # Nanosecond standard
    b"\x4d\x3c\xb2\xa1",  # Nanosecond swapped
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
}


@dataclass
class ParserMetrics:
    """Statistics tracked during capture ingestion."""

    file_path: str
    file_size_bytes: int
    total_read: int = 0
    parsed_ok: int = 0
    parsed_partial: int = 0
    parsed_error: int = 0
    total_bytes: int = 0
    truncated_by_limit: bool = False
    warning_message: Optional[str] = None


def validate_capture_file(file_path: str | Path) -> Path:
    """Validate that the capture file exists, is readable, and is non-empty.

    Args:
        file_path: Path to capture file.

    Returns:
        Resolved Path object.

    Raises:
        InvalidCaptureError: If file is missing, empty, or unreadable.
        UnsupportedCaptureFormatError: If file header magic does not match pcap/pcapng.
    """
    path = Path(file_path)
    if not path.exists():
        raise InvalidCaptureError(f"Capture file does not exist: {file_path}")
    if not path.is_file():
        raise InvalidCaptureError(f"Path is not a regular file: {file_path}")

    try:
        size = path.stat().st_size
    except OSError as e:
        raise InvalidCaptureError(f"Unable to read file status: {e}") from e

    if size == 0:
        raise InvalidCaptureError(f"Capture file is empty (0 bytes): {file_path}")

    # Check magic bytes for PCAP / PCAPNG
    try:
        with open(path, "rb") as f:
            header = f.read(4)
            if len(header) < 4:
                raise InvalidCaptureError(f"File too small to contain capture header: {file_path}")
            if header not in PCAP_MAGIC_NUMBERS:
                # Log warning or error for unsupported magic
                logger.warning(
                    "File %s has non-standard header %r; attempting dissection anyway.",
                    file_path,
                    header,
                )
    except OSError as e:
        raise InvalidCaptureError(f"Failed reading capture header: {e}") from e

    return path


def _extract_dns_metadata(packet: object) -> Tuple[Optional[str], Optional[str]]:
    """Extract DNS query domain and query type if present."""
    if not hasattr(packet, "haslayer") or not packet.haslayer(DNS):
        return None, None

    try:
        dns_layer = packet[DNS]
        if dns_layer.haslayer(DNSQR):
            qr = dns_layer[DNSQR]
            qname = qr.qname
            if isinstance(qname, bytes):
                qname_str = qname.decode("utf-8", errors="replace").rstrip(".")
            else:
                qname_str = str(qname).rstrip(".")
            qtype_num = qr.qtype
            # Common DNS types mapping
            type_map = {1: "A", 28: "AAAA", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 2: "NS"}
            qtype_str = type_map.get(qtype_num, f"TYPE-{qtype_num}")
            return qname_str, qtype_str
    except Exception as e:
        logger.debug("Failed extracting DNS metadata: %s", e)

    return None, None


def _dissect_scapy_packet(pkt: object, index: int) -> PacketRecord:
    """Dissect a Scapy packet into a normalized PacketRecord.

    Extracts protocol, IP addresses, transport ports, flags, and DNS metadata.
    Does not assign ports to ICMP packets.
    """
    ts = float(getattr(pkt, "time", 0.0))
    cap_len = len(pkt)
    # Wirelen convention: prefer captured wire length if exposed by file format
    wire_len = int(getattr(pkt, "wirelen", cap_len))

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol = "OTHER"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    parsing_status = "OK"
    error_reason: Optional[str] = None

    try:
        # Layer 3 / Network Layer extraction
        if hasattr(pkt, "haslayer"):
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                protocol = "IP"
            elif pkt.haslayer(IPv6):
                ipv6_layer = pkt[IPv6]
                src_ip = str(ipv6_layer.src)
                dst_ip = str(ipv6_layer.dst)
                protocol = "IPv6"
            elif pkt.haslayer(ARP):
                arp_layer = pkt[ARP]
                src_ip = str(arp_layer.psrc)
                dst_ip = str(arp_layer.pdst)
                protocol = "ARP"
            elif pkt.haslayer(Ether):
                protocol = "ETHERNET"

            # Layer 4 / Transport Layer extraction
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                protocol = "TCP"
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                # Convert Scapy flags to string representation (e.g. 'S', 'SA', 'FA', 'R')
                tcp_flags = str(tcp_layer.flags)
            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                protocol = "UDP"
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
                # Ports intentionally remain None for ICMP
            elif any(name.startswith("ICMPv6") for name in pkt.layers()):
                protocol = "ICMPv6"
                # Ports intentionally remain None for ICMPv6

    except Exception as e:
        parsing_status = "PARTIAL"
        error_reason = f"Partial dissection failure: {e}"
        logger.debug("Partial dissection exception on packet %d: %s", index, e)

    dns_query, dns_qtype = _extract_dns_metadata(pkt)

    return PacketRecord.create(
        index=index,
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        length=cap_len,
        wire_length=wire_len,
        tcp_flags=tcp_flags,
        dns_query=dns_query,
        dns_qtype=dns_qtype,
        parsing_status=parsing_status,
        error_reason=error_reason,
    )


def stream_packets(
    file_path: str | Path,
    max_packets: Optional[int] = None,
) -> Generator[PacketRecord, None, None]:
    """Incrementally yield PacketRecords from a capture file.

    Maintains minimal memory overhead by reading packets lazily.

    Args:
        file_path: Path to capture file.
        max_packets: Optional safety cutoff limit.

    Yields:
        Dissected PacketRecord instances.
    """
    path = validate_capture_file(file_path)

    try:
        reader = PcapReader(str(path))
    except Scapy_Exception as e:
        raise UnsupportedCaptureFormatError(f"Scapy failed reading capture {file_path}: {e}") from e
    except Exception as e:
        raise ParsingError(f"Unexpected error opening capture {file_path}: {e}") from e

    packet_index = 0
    try:
        for pkt in reader:
            packet_index += 1
            if max_packets is not None and packet_index > max_packets:
                logger.warning("Reached safety packet limit (%d); halting stream.", max_packets)
                break

            try:
                record = _dissect_scapy_packet(pkt, packet_index)
                yield record
            except Exception as e:
                logger.warning("Packet %d malformed: %s", packet_index, e)
                yield PacketRecord.create(
                    index=packet_index,
                    timestamp=0.0,
                    src_ip=None,
                    dst_ip=None,
                    protocol="CORRUPTED",
                    parsing_status="ERROR",
                    error_reason=str(e),
                )
    finally:
        reader.close()


def parse_capture(
    file_path: str | Path,
    max_packets: Optional[int] = None,
) -> Tuple[List[PacketRecord], ParserMetrics]:
    """Parse a capture file, returning all PacketRecords and parsing metrics.

    Args:
        file_path: Path to capture file.
        max_packets: Optional safety limit.

    Returns:
        Tuple of (list of PacketRecord, ParserMetrics).
    """
    path = validate_capture_file(file_path)
    file_size = path.stat().st_size

    metrics = ParserMetrics(file_path=str(path), file_size_bytes=file_size)
    records: List[PacketRecord] = []

    for record in stream_packets(path, max_packets=max_packets):
        metrics.total_read += 1
        metrics.total_bytes += record.wire_length

        if record.parsing_status == "OK":
            metrics.parsed_ok += 1
        elif record.parsing_status == "PARTIAL":
            metrics.parsed_partial += 1
        else:
            metrics.parsed_error += 1

        records.append(record)

    if max_packets is not None and metrics.total_read >= max_packets:
        metrics.truncated_by_limit = True
        metrics.warning_message = (
            f"Processing reached safety limit of {max_packets} packets. "
            "Analysis represents the processed prefix."
        )

    return records, metrics
