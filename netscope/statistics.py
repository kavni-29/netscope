"""NetScope statistical analysis engine.

Computes comprehensive protocol distributions, endpoint rankings, packet length
descriptive statistics (mean, median, percentiles), and time-bucketed traffic volume series.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from netscope.models import FlowRecord, PacketRecord


@dataclass
class PacketSizeStatistics:
    """Descriptive statistics for packet wire lengths."""

    count: int = 0
    min_length: int = 0
    max_length: int = 0
    mean_length: float = 0.0
    median_length: float = 0.0
    percentile_25: float = 0.0
    percentile_75: float = 0.0
    percentile_95: float = 0.0
    std_dev: float = 0.0
    length_bins: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to dictionary."""
        return {
            "count": self.count,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "mean_length": round(self.mean_length, 2),
            "median_length": round(self.median_length, 2),
            "percentile_25": round(self.percentile_25, 2),
            "percentile_75": round(self.percentile_75, 2),
            "percentile_95": round(self.percentile_95, 2),
            "std_dev": round(self.std_dev, 2),
            "length_bins": self.length_bins,
        }


@dataclass
class ProtocolMetric:
    """Metrics for an individual network protocol."""

    protocol: str
    packet_count: int
    byte_count: int
    packet_percentage: float
    byte_percentage: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary."""
        return {
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "packet_percentage": round(self.packet_percentage, 2),
            "byte_percentage": round(self.byte_percentage, 2),
        }


@dataclass
class EndpointMetric:
    """Metrics for an observed IP endpoint."""

    endpoint: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    distinct_dest_ports: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary."""
        return {
            "endpoint": self.endpoint,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "distinct_dest_ports": self.distinct_dest_ports,
        }


@dataclass
class TimeBucket:
    """Traffic metrics for a discrete time window."""

    bucket_index: int
    relative_start_sec: float
    relative_end_sec: float
    epoch_start_sec: float
    epoch_end_sec: float
    packet_count: int
    byte_count: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert bucket to dictionary."""
        return {
            "bucket_index": self.bucket_index,
            "relative_start_sec": round(self.relative_start_sec, 2),
            "relative_end_sec": round(self.relative_end_sec, 2),
            "epoch_start_sec": round(self.epoch_start_sec, 4),
            "epoch_end_sec": round(self.epoch_end_sec, 4),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
        }


@dataclass
class StatisticsReport:
    """Consolidated statistical report for a capture analysis."""

    total_packets: int
    total_bytes: int
    capture_start_ts: Optional[float]
    capture_end_ts: Optional[float]
    capture_duration_sec: float
    protocols: Dict[str, ProtocolMetric]
    packet_sizes: PacketSizeStatistics
    endpoints: Dict[str, EndpointMetric]
    top_sources: List[EndpointMetric]
    top_destinations: List[EndpointMetric]
    top_talkers_by_bytes: List[EndpointMetric]
    time_series: List[TimeBucket]
    traffic_concentration_top1_pct: float = 0.0
    traffic_concentration_top3_pct: float = 0.0
    traffic_concentration_top5_pct: float = 0.0


def compute_packet_size_statistics(packets: List[PacketRecord]) -> PacketSizeStatistics:
    """Compute descriptive statistics and binned distribution for packet lengths.

    Handles empty collections safely without raising division errors.
    """
    if not packets:
        return PacketSizeStatistics()

    lengths = [p.wire_length for p in packets]
    n = len(lengths)
    arr = np.array(lengths, dtype=np.int64)

    min_l = int(np.min(arr))
    max_l = int(np.max(arr))
    mean_l = float(np.mean(arr))
    median_l = float(np.median(arr))
    p25 = float(np.percentile(arr, 25))
    p75 = float(np.percentile(arr, 75))
    p95 = float(np.percentile(arr, 95))
    std_l = float(np.std(arr)) if n > 1 else 0.0

    # Categorize into conventional ethernet frame size bins
    bins = {
        "0-64 B": 0,
        "65-128 B": 0,
        "129-256 B": 0,
        "257-512 B": 0,
        "513-1024 B": 0,
        "1025-1518 B": 0,
        "1519+ B": 0,
    }
    for length in lengths:
        if length <= 64:
            bins["0-64 B"] += 1
        elif length <= 128:
            bins["65-128 B"] += 1
        elif length <= 256:
            bins["129-256 B"] += 1
        elif length <= 512:
            bins["257-512 B"] += 1
        elif length <= 1024:
            bins["513-1024 B"] += 1
        elif length <= 1518:
            bins["1025-1518 B"] += 1
        else:
            bins["1519+ B"] += 1

    return PacketSizeStatistics(
        count=n,
        min_length=min_l,
        max_length=max_l,
        mean_length=mean_l,
        median_length=median_l,
        percentile_25=p25,
        percentile_75=p75,
        percentile_95=p95,
        std_dev=std_l,
        length_bins=bins,
    )


def compute_protocol_metrics(packets: List[PacketRecord]) -> Dict[str, ProtocolMetric]:
    """Calculate packet count, byte volume, and percentages by protocol."""
    total_packets = len(packets)
    total_bytes = sum(p.wire_length for p in packets)

    proto_packets: Dict[str, int] = Counter()
    proto_bytes: Dict[str, int] = Counter()

    for p in packets:
        proto = p.protocol or "UNKNOWN"
        proto_packets[proto] += 1
        proto_bytes[proto] += p.wire_length

    metrics: Dict[str, ProtocolMetric] = {}
    for proto, count in proto_packets.items():
        b_count = proto_bytes[proto]
        pkt_pct = (count / total_packets * 100.0) if total_packets > 0 else 0.0
        byte_pct = (b_count / total_bytes * 100.0) if total_bytes > 0 else 0.0

        metrics[proto] = ProtocolMetric(
            protocol=proto,
            packet_count=count,
            byte_count=b_count,
            packet_percentage=pkt_pct,
            byte_percentage=byte_pct,
        )

    return metrics


def compute_endpoint_metrics(packets: List[PacketRecord]) -> Dict[str, EndpointMetric]:
    """Compute bidirectional metrics and port diversity per IP endpoint."""
    endpoints: Dict[str, EndpointMetric] = {}
    dest_ports_by_src: Dict[str, set] = defaultdict(set)

    for p in packets:
        wire_len = p.wire_length

        if p.src_ip:
            if p.src_ip not in endpoints:
                endpoints[p.src_ip] = EndpointMetric(endpoint=p.src_ip)
            ep = endpoints[p.src_ip]
            ep.packets_sent += 1
            ep.bytes_sent += wire_len
            ep.total_packets += 1
            ep.total_bytes += wire_len

            if p.dst_port is not None:
                dest_ports_by_src[p.src_ip].add(p.dst_port)

        if p.dst_ip:
            if p.dst_ip not in endpoints:
                endpoints[p.dst_ip] = EndpointMetric(endpoint=p.dst_ip)
            ep = endpoints[p.dst_ip]
            ep.packets_received += 1
            ep.bytes_received += wire_len
            ep.total_packets += 1
            ep.total_bytes += wire_len

    # Set distinct destination ports contacted
    for src_ip, ports in dest_ports_by_src.items():
        if src_ip in endpoints:
            endpoints[src_ip].distinct_dest_ports = len(ports)

    return endpoints


def compute_time_series(
    packets: List[PacketRecord],
    interval_sec: float = 1.0,
) -> List[TimeBucket]:
    """Aggregate traffic volume and packet counts into fixed-width time intervals.

    Handles empty intervals within the capture span.
    """
    if not packets or interval_sec <= 0:
        return []

    valid_ts = [p.timestamp for p in packets if p.timestamp > 0]
    if not valid_ts:
        return []

    start_ts = min(valid_ts)
    end_ts = max(valid_ts)
    span = max(0.0, end_ts - start_ts)

    num_buckets = max(1, math.ceil(span / interval_sec) if span > 0 else 1)
    # Guard against excessively large bucket arrays for sparse long captures
    if num_buckets > 50000:
        interval_sec = span / 500.0
        num_buckets = 500

    buckets: List[TimeBucket] = []
    for i in range(num_buckets):
        b_epoch_start = start_ts + (i * interval_sec)
        b_epoch_end = b_epoch_start + interval_sec
        b_rel_start = i * interval_sec
        b_rel_end = (i + 1) * interval_sec

        buckets.append(
            TimeBucket(
                bucket_index=i,
                relative_start_sec=b_rel_start,
                relative_end_sec=b_rel_end,
                epoch_start_sec=b_epoch_start,
                epoch_end_sec=b_epoch_end,
                packet_count=0,
                byte_count=0,
            )
        )

    for p in packets:
        if p.timestamp < start_ts:
            continue
        offset = p.timestamp - start_ts
        idx = min(int(offset // interval_sec), num_buckets - 1)
        buckets[idx].packet_count += 1
        buckets[idx].byte_count += p.wire_length

    return buckets


def calculate_statistics(
    packets: List[PacketRecord],
    flows: Optional[List[FlowRecord]] = None,
    interval_sec: float = 1.0,
) -> StatisticsReport:
    """Calculate comprehensive statistical report for processed capture packets."""
    total_packets = len(packets)
    total_bytes = sum(p.wire_length for p in packets)

    valid_ts = [p.timestamp for p in packets if p.timestamp > 0]
    start_ts = min(valid_ts) if valid_ts else None
    end_ts = max(valid_ts) if valid_ts else None
    duration = (end_ts - start_ts) if (start_ts and end_ts and end_ts >= start_ts) else 0.0

    protocols = compute_protocol_metrics(packets)
    packet_sizes = compute_packet_size_statistics(packets)
    endpoints = compute_endpoint_metrics(packets)
    time_series = compute_time_series(packets, interval_sec=interval_sec)

    # Rankings
    all_eps = list(endpoints.values())
    top_sources = sorted(all_eps, key=lambda e: e.packets_sent, reverse=True)[:10]
    top_destinations = sorted(all_eps, key=lambda e: e.packets_received, reverse=True)[:10]
    top_talkers_by_bytes = sorted(all_eps, key=lambda e: e.total_bytes, reverse=True)[:10]

    # Traffic concentration ratios
    sorted_by_packets = sorted(all_eps, key=lambda e: e.total_packets, reverse=True)
    top1_pct = (sorted_by_packets[0].total_packets / total_packets * 100.0) if sorted_by_packets and total_packets > 0 else 0.0
    top3_pct = (sum(e.total_packets for e in sorted_by_packets[:3]) / total_packets * 100.0) if sorted_by_packets and total_packets > 0 else 0.0
    top5_pct = (sum(e.total_packets for e in sorted_by_packets[:5]) / total_packets * 100.0) if sorted_by_packets and total_packets > 0 else 0.0

    return StatisticsReport(
        total_packets=total_packets,
        total_bytes=total_bytes,
        capture_start_ts=start_ts,
        capture_end_ts=end_ts,
        capture_duration_sec=duration,
        protocols=protocols,
        packet_sizes=packet_sizes,
        endpoints=endpoints,
        top_sources=top_sources,
        top_destinations=top_destinations,
        top_talkers_by_bytes=top_talkers_by_bytes,
        time_series=time_series,
        traffic_concentration_top1_pct=round(top1_pct, 2),
        traffic_concentration_top3_pct=round(top3_pct, 2),
        traffic_concentration_top5_pct=round(top5_pct, 2),
    )
