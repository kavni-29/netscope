"""Unit tests for NetScope statistical calculations module."""

import pytest

from netscope.models import PacketRecord
from netscope.statistics import (
    calculate_statistics,
    compute_endpoint_metrics,
    compute_packet_size_statistics,
    compute_protocol_metrics,
    compute_time_series,
)


def test_empty_packets_statistics():
    """Verify statistics calculation handles empty packet lists gracefully."""
    stats = calculate_statistics([])
    assert stats.total_packets == 0
    assert stats.total_bytes == 0
    assert stats.capture_start_ts is None
    assert stats.capture_end_ts is None
    assert stats.capture_duration_sec == 0.0
    assert len(stats.protocols) == 0
    assert stats.packet_sizes.count == 0
    assert stats.packet_sizes.mean_length == 0.0
    assert len(stats.endpoints) == 0
    assert len(stats.time_series) == 0


def test_protocol_metrics_and_percentages():
    """Verify accurate packet and byte share calculations by protocol."""
    pkts = [
        PacketRecord.create(1, 10.0, "1.1.1.1", "2.2.2.2", "TCP", 1000, 80, length=100, wire_length=100),
        PacketRecord.create(2, 10.1, "1.1.1.1", "2.2.2.2", "TCP", 1000, 80, length=300, wire_length=300),
        PacketRecord.create(3, 10.2, "1.1.1.1", "2.2.2.2", "UDP", 1000, 53, length=100, wire_length=100),
    ]

    m = compute_protocol_metrics(pkts)
    assert len(m) == 2
    assert m["TCP"].packet_count == 2
    assert m["TCP"].byte_count == 400
    assert m["TCP"].packet_percentage == pytest.approx(66.67, 0.1)
    assert m["TCP"].byte_percentage == pytest.approx(80.0, 0.1)

    assert m["UDP"].packet_count == 1
    assert m["UDP"].byte_count == 100
    assert m["UDP"].packet_percentage == pytest.approx(33.33, 0.1)
    assert m["UDP"].byte_percentage == pytest.approx(20.0, 0.1)


def test_packet_size_descriptive_statistics():
    """Verify min, max, mean, median, percentiles and bins calculation."""
    lengths = [50, 100, 150, 200, 500, 1500]
    pkts = [
        PacketRecord.create(i + 1, 10.0 + i, "1.1.1.1", "2.2.2.2", "TCP", 100, 200, length=l, wire_length=l)
        for i, l in enumerate(lengths)
    ]

    size_stats = compute_packet_size_statistics(pkts)
    assert size_stats.count == 6
    assert size_stats.min_length == 50
    assert size_stats.max_length == 1500
    assert size_stats.mean_length == pytest.approx(2500.0 / 6.0)
    assert size_stats.median_length == pytest.approx(175.0)
    assert size_stats.length_bins["0-64 B"] == 1
    assert size_stats.length_bins["65-128 B"] == 1
    assert size_stats.length_bins["129-256 B"] == 2
    assert size_stats.length_bins["257-512 B"] == 1
    assert size_stats.length_bins["1025-1518 B"] == 1


def test_endpoint_metrics_and_port_diversity():
    """Verify endpoint volume and distinct destination port count calculation."""
    pkts = [
        PacketRecord.create(1, 1.0, "192.168.1.100", "10.0.0.1", "TCP", 1000, 80, length=100),
        PacketRecord.create(2, 1.1, "192.168.1.100", "10.0.0.1", "TCP", 1001, 443, length=100),
        PacketRecord.create(3, 1.2, "192.168.1.100", "10.0.0.1", "TCP", 1002, 80, length=100),
    ]

    eps = compute_endpoint_metrics(pkts)
    src_ep = eps["192.168.1.100"]
    assert src_ep.packets_sent == 3
    assert src_ep.bytes_sent == 300
    assert src_ep.distinct_dest_ports == 2  # 80 and 443


def test_time_series_interval_buckets():
    """Verify time series interval bucket creation and aggregation."""
    pkts = [
        PacketRecord.create(1, 10.1, "1.1.1.1", "2.2.2.2", "TCP", length=100),
        PacketRecord.create(2, 10.9, "1.1.1.1", "2.2.2.2", "TCP", length=200),
        PacketRecord.create(3, 11.2, "1.1.1.1", "2.2.2.2", "TCP", length=150),
    ]

    buckets = compute_time_series(pkts, interval_sec=1.0)
    assert len(buckets) == 2
    assert buckets[0].packet_count == 2
    assert buckets[0].byte_count == 300
    assert buckets[1].packet_count == 1
    assert buckets[1].byte_count == 150
