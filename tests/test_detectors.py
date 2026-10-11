"""Unit tests for NetScope explainable anomaly detection rules and boundary cases."""

import pytest

from netscope.config import DetectionConfig
from netscope.detectors import (
    HighPacketRateDetector,
    PortDiversityDetector,
    RepeatedCommunicationDetector,
    SynWithoutAckDetector,
    TrafficConcentrationDetector,
    VolumeDeviationDetector,
)
from netscope.models import PacketRecord
from netscope.statistics import calculate_statistics


def test_high_packet_rate_boundaries():
    """Test HighPacketRateDetector boundary conditions (below, at, above threshold)."""
    detector = HighPacketRateDetector()
    cfg = DetectionConfig(high_packet_rate_threshold=5, high_packet_rate_window_sec=1.0)

    # 1. Below threshold (4 packets)
    pkts_below = [
        PacketRecord.create(i + 1, 10.0 + (i * 0.1), "1.1.1.1", "2.2.2.2", "TCP", length=60)
        for i in range(4)
    ]
    stats_below = calculate_statistics(pkts_below)
    assert len(detector.evaluate(pkts_below, [], stats_below, cfg)) == 0

    # 2. Exactly at threshold (5 packets -> >5 should not trigger)
    pkts_at = [
        PacketRecord.create(i + 1, 10.0 + (i * 0.1), "1.1.1.1", "2.2.2.2", "TCP", length=60)
        for i in range(5)
    ]
    stats_at = calculate_statistics(pkts_at)
    assert len(detector.evaluate(pkts_at, [], stats_at, cfg)) == 0

    # 3. Above threshold (6 packets in 1s window -> triggers alert)
    pkts_above = [
        PacketRecord.create(i + 1, 10.0 + (i * 0.1), "1.1.1.1", "2.2.2.2", "TCP", length=60)
        for i in range(6)
    ]
    stats_above = calculate_statistics(pkts_above)
    alerts = detector.evaluate(pkts_above, [], stats_above, cfg)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE_HIGH_PACKET_RATE"
    assert alerts[0].endpoint == "1.1.1.1"
    assert "6 packets" in alerts[0].observed_value


def test_port_diversity_boundaries():
    """Test PortDiversityDetector boundary conditions."""
    detector = PortDiversityDetector()
    cfg = DetectionConfig(port_diversity_threshold=3, port_diversity_window_sec=5.0)

    # 1. Below threshold: 2 distinct ports
    pkts_below = [
        PacketRecord.create(1, 1.0, "10.0.0.1", "10.0.0.2", "TCP", 1000, 80, length=50),
        PacketRecord.create(2, 1.1, "10.0.0.1", "10.0.0.2", "TCP", 1001, 443, length=50),
    ]
    stats_below = calculate_statistics(pkts_below)
    assert len(detector.evaluate(pkts_below, [], stats_below, cfg)) == 0

    # 2. Exactly at threshold: 3 distinct ports (>3 should not trigger)
    pkts_at = [
        PacketRecord.create(1, 1.0, "10.0.0.1", "10.0.0.2", "TCP", 1000, 80, length=50),
        PacketRecord.create(2, 1.1, "10.0.0.1", "10.0.0.2", "TCP", 1001, 443, length=50),
        PacketRecord.create(3, 1.2, "10.0.0.1", "10.0.0.2", "TCP", 1002, 8080, length=50),
    ]
    stats_at = calculate_statistics(pkts_at)
    assert len(detector.evaluate(pkts_at, [], stats_at, cfg)) == 0

    # 3. Above threshold: 4 distinct ports -> triggers
    pkts_above = [
        PacketRecord.create(1, 1.0, "10.0.0.1", "10.0.0.2", "TCP", 1000, 80, length=50),
        PacketRecord.create(2, 1.1, "10.0.0.1", "10.0.0.2", "TCP", 1001, 443, length=50),
        PacketRecord.create(3, 1.2, "10.0.0.1", "10.0.0.2", "TCP", 1002, 8080, length=50),
        PacketRecord.create(4, 1.3, "10.0.0.1", "10.0.0.2", "TCP", 1003, 9000, length=50),
    ]
    stats_above = calculate_statistics(pkts_above)
    alerts = detector.evaluate(pkts_above, [], stats_above, cfg)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE_PORT_DIVERSITY"
    assert "4 distinct ports" in alerts[0].observed_value


def test_syn_without_ack_detector():
    """Test SynWithoutAckDetector logic, ratios, and sample size constraints."""
    detector = SynWithoutAckDetector()
    cfg = DetectionConfig(syn_ratio_threshold=0.8, syn_min_packets=5)

    # 1. Below min sample size (4 SYN packets < 5 min required -> no alert)
    pkts_small = [
        PacketRecord.create(i + 1, 1.0 + i, "10.0.0.5", "10.0.0.1", "TCP", 1000 + i, 80, tcp_flags="S", length=60)
        for i in range(4)
    ]
    stats_small = calculate_statistics(pkts_small)
    assert len(detector.evaluate(pkts_small, [], stats_small, cfg)) == 0

    # 2. Sample size 10, but balanced handshakes (ratio 0.5 < 0.8 -> no alert)
    pkts_balanced = [
        PacketRecord.create(i + 1, 1.0 + i, "10.0.0.5", "10.0.0.1", "TCP", 1000 + i, 80,
                            tcp_flags="S" if i < 5 else "A", length=60)
        for i in range(10)
    ]
    stats_balanced = calculate_statistics(pkts_balanced)
    assert len(detector.evaluate(pkts_balanced, [], stats_balanced, cfg)) == 0

    # 3. Ratio at threshold: 8 out of 10 are SYN without ACK (80% >= 80% -> triggers)
    pkts_trigger = [
        PacketRecord.create(i + 1, 1.0 + i, "10.0.0.5", "10.0.0.1", "TCP", 1000 + i, 80,
                            tcp_flags="S" if i < 8 else "A", length=60)
        for i in range(10)
    ]
    stats_trigger = calculate_statistics(pkts_trigger)
    alerts = detector.evaluate(pkts_trigger, [], stats_trigger, cfg)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE_SYN_WITHOUT_ACK"
    assert "80.0%" in alerts[0].observed_value


def test_volume_deviation_detector():
    """Test VolumeDeviationDetector baseline requirements and z-score spike trigger."""
    detector = VolumeDeviationDetector()
    cfg = DetectionConfig(
        volume_deviation_zscore=2.0,
        volume_deviation_min_intervals=4,
        volume_deviation_interval_sec=1.0,
    )

    # 1. Insufficient intervals (< 4 intervals -> no alert)
    pkts_few = [
        PacketRecord.create(1, 1.0, "1.1.1.1", "2.2.2.2", "TCP", length=100),
        PacketRecord.create(2, 2.0, "1.1.1.1", "2.2.2.2", "TCP", length=100),
    ]
    stats_few = calculate_statistics(pkts_few, interval_sec=1.0)
    assert len(detector.evaluate(pkts_few, [], stats_few, cfg)) == 0

    # 2. Zero variance: 5 intervals with exact same 100 bytes each -> no alert
    pkts_equal = [
        PacketRecord.create(i + 1, 1.0 + i, "1.1.1.1", "2.2.2.2", "TCP", length=100)
        for i in range(5)
    ]
    stats_equal = calculate_statistics(pkts_equal, interval_sec=1.0)
    assert len(detector.evaluate(pkts_equal, [], stats_equal, cfg)) == 0

    # 3. Outlier spike: 5 intervals of ~100 bytes + 1 interval with 50,000 bytes
    pkts_spike = [
        PacketRecord.create(i + 1, 1.0 + i, "1.1.1.1", "2.2.2.2", "TCP", length=100)
        for i in range(5)
    ]
    for k in range(50):
        pkts_spike.append(
            PacketRecord.create(10 + k, 6.5, "1.1.1.1", "2.2.2.2", "TCP", length=1000)
        )
    stats_spike = calculate_statistics(pkts_spike, interval_sec=1.0)
    alerts = detector.evaluate(pkts_spike, [], stats_spike, cfg)
    assert len(alerts) >= 1
    assert alerts[0].rule_id == "RULE_VOLUME_DEVIATION"
    assert "Z-score:" in alerts[0].observed_value


def test_traffic_concentration_detector():
    """Test TrafficConcentrationDetector threshold triggers."""
    detector = TrafficConcentrationDetector()
    cfg = DetectionConfig(traffic_concentration_threshold=0.6, traffic_concentration_min_packets=10)

    # 10 packets total, 7 from 10.0.0.1 (70% >= 60% -> triggers)
    pkts = [
        PacketRecord.create(i + 1, 1.0 + i, "10.0.0.1" if i < 7 else "10.0.0.2", f"192.168.1.{i + 1}", "TCP", length=100)
        for i in range(10)
    ]
    stats = calculate_statistics(pkts)
    alerts = detector.evaluate(pkts, [], stats, cfg)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE_TRAFFIC_CONCENTRATION"
    assert alerts[0].endpoint == "10.0.0.1"


def test_repeated_communication_detector():
    """Test RepeatedCommunicationDetector burst detection."""
    detector = RepeatedCommunicationDetector()
    cfg = DetectionConfig(repeated_comm_threshold=5, repeated_comm_window_sec=2.0)

    # 6 packets to identical (10.0.0.1 -> 10.0.0.2:80) within 1.0 second -> triggers
    pkts = [
        PacketRecord.create(i + 1, 10.0 + (i * 0.1), "10.0.0.1", "10.0.0.2", "TCP", 1000 + i, 80, length=60)
        for i in range(6)
    ]
    stats = calculate_statistics(pkts)
    alerts = detector.evaluate(pkts, [], stats, cfg)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE_REPEATED_COMMUNICATION"
    assert "10.0.0.1 -> 10.0.0.2:80" in alerts[0].endpoint
