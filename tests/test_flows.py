"""Unit tests for NetScope bidirectional flow aggregation engine."""

from netscope.flows import FlowAggregator, aggregate_flows
from netscope.models import FlowKey, PacketRecord


def test_bidirectional_flow_key_ordering():
    """Verify that (A, B) and (B, A) construct an identical FlowKey."""
    key1 = FlowKey.build("TCP", "192.168.1.10", 50000, "10.0.0.1", 80)
    key2 = FlowKey.build("TCP", "10.0.0.1", 80, "192.168.1.10", 50000)

    assert key1 == key2
    assert key1.endpoint_a == ("10.0.0.1", 80)
    assert key1.endpoint_b == ("192.168.1.10", 50000)


def test_distinct_ports_distinct_flows():
    """Verify that different ports generate distinct bidirectional flows."""
    key1 = FlowKey.build("TCP", "10.0.0.1", 80, "192.168.1.10", 50000)
    key2 = FlowKey.build("TCP", "10.0.0.1", 443, "192.168.1.10", 50000)
    assert key1 != key2


def test_distinct_protocols_distinct_flows():
    """Verify that identical endpoints with different protocols form distinct flows."""
    key_tcp = FlowKey.build("TCP", "10.0.0.1", 53, "192.168.1.10", 50000)
    key_udp = FlowKey.build("UDP", "10.0.0.1", 53, "192.168.1.10", 50000)
    assert key_tcp != key_udp


def test_bidirectional_aggregation_directional_counts():
    """Test packet and byte attribution in forward and reverse directions."""
    agg = FlowAggregator()

    # Forward packet (A -> B)
    p1 = PacketRecord.create(
        index=1,
        timestamp=100.0,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.10",
        protocol="TCP",
        src_port=80,
        dst_port=50000,
        length=100,
        wire_length=100,
        tcp_flags="SA",
    )
    # Reverse packet (B -> A)
    p2 = PacketRecord.create(
        index=2,
        timestamp=102.5,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        protocol="TCP",
        src_port=50000,
        dst_port=80,
        length=200,
        wire_length=200,
        tcp_flags="A",
    )

    agg.add_packet(p1)
    agg.add_packet(p2)

    flows = agg.get_flows()
    assert len(flows) == 1
    flow = flows[0]

    assert flow.total_packets == 2
    assert flow.total_bytes == 300
    assert flow.packets_a_to_b == 1
    assert flow.packets_b_to_a == 1
    assert flow.bytes_a_to_b == 100
    assert flow.bytes_b_to_a == 200
    assert flow.duration == 2.5
    assert flow.first_timestamp == 100.0
    assert flow.last_timestamp == 102.5
    assert flow.tcp_flag_counts["SYN"] == 1
    assert flow.tcp_flag_counts["ACK"] == 2


def test_single_packet_zero_duration():
    """Single packet flows must have exactly 0.0 duration."""
    agg = FlowAggregator()
    p = PacketRecord.create(
        index=1,
        timestamp=100.0,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        protocol="UDP",
        src_port=123,
        dst_port=123,
        length=50,
    )
    agg.add_packet(p)
    flows = agg.get_flows()
    assert len(flows) == 1
    assert flows[0].total_packets == 1
    assert flows[0].duration == 0.0


def test_out_of_order_timestamps():
    """Verify that out-of-order packets correctly adjust first and last timestamps."""
    agg = FlowAggregator()

    p_later = PacketRecord.create(
        index=1,
        timestamp=105.0,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        protocol="TCP",
        src_port=1000,
        dst_port=2000,
        length=60,
    )
    p_earlier = PacketRecord.create(
        index=2,
        timestamp=101.0,
        src_ip="2.2.2.2",
        dst_ip="1.1.1.1",
        protocol="TCP",
        src_port=2000,
        dst_port=1000,
        length=60,
    )

    agg.add_packet(p_later)
    agg.add_packet(p_earlier)

    flow = agg.get_flows()[0]
    assert flow.first_timestamp == 101.0
    assert flow.last_timestamp == 105.0
    assert flow.duration == 4.0


def test_icmp_flow_aggregation_no_ports():
    """Verify ICMP packets aggregate without ports."""
    agg = FlowAggregator()
    p1 = PacketRecord.create(
        index=1,
        timestamp=10.0,
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        protocol="ICMP",
        src_port=None,
        dst_port=None,
        length=84,
    )
    p2 = PacketRecord.create(
        index=2,
        timestamp=10.1,
        src_ip="8.8.8.8",
        dst_ip="192.168.1.1",
        protocol="ICMP",
        src_port=None,
        dst_port=None,
        length=84,
    )
    agg.add_packet(p1)
    agg.add_packet(p2)

    flows = agg.get_flows()
    assert len(flows) == 1
    f = flows[0]
    assert f.protocol == "ICMP"
    assert f.endpoint_a_port is None
    assert f.endpoint_b_port is None
    assert f.total_packets == 2
