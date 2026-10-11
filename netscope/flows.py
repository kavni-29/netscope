"""NetScope bidirectional network flow aggregation engine.

Aggregates individual packets into bidirectional network flows using
deterministic canonical flow keys. Calculates directional packet and byte
counters, durations, TCP flag counts, and associated DNS metadata.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from netscope.models import FlowKey, FlowRecord, PacketRecord


class FlowAggregator:
    """Aggregates packets into bidirectional flows with O(1) dictionary lookups."""

    def __init__(self) -> None:
        self._flows: Dict[FlowKey, FlowRecord] = {}

    def add_packet(self, packet: PacketRecord) -> Optional[FlowRecord]:
        """Aggregate an individual packet into its corresponding bidirectional flow.

        Packets without endpoints (e.g. corrupted frames) are ignored.

        Args:
            packet: PacketRecord to process.

        Returns:
            Updated FlowRecord or None if packet could not be keyed.
        """
        # Packets without IP or valid address cannot form an IP network flow
        if not packet.src_ip or not packet.dst_ip:
            return None

        # Build canonical flow key
        key = FlowKey.build(
            protocol=packet.protocol,
            src_ip=packet.src_ip,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port,
        )

        flow = self._flows.get(key)
        bytes_count = packet.wire_length or packet.length

        if flow is None:
            # Construct human-readable flow ID
            ep_a_str = (
                f"{key.endpoint_a[0]}:{key.endpoint_a[1]}"
                if key.endpoint_a[1] is not None
                else key.endpoint_a[0]
            )
            ep_b_str = (
                f"{key.endpoint_b[0]}:{key.endpoint_b[1]}"
                if key.endpoint_b[1] is not None
                else key.endpoint_b[0]
            )
            flow_id = f"{key.protocol}:{ep_a_str}<->{ep_b_str}"

            flow = FlowRecord(
                flow_id=flow_id,
                protocol=key.protocol,
                endpoint_a_ip=key.endpoint_a[0],
                endpoint_a_port=key.endpoint_a[1],
                endpoint_b_ip=key.endpoint_b[0],
                endpoint_b_port=key.endpoint_b[1],
                first_timestamp=packet.timestamp,
                last_timestamp=packet.timestamp,
                packets_a_to_b=0,
                packets_b_to_a=0,
                bytes_a_to_b=0,
                bytes_b_to_a=0,
                total_packets=0,
                total_bytes=0,
                duration=0.0,
                tcp_flag_counts={},
                dns_queries=[],
            )
            self._flows[key] = flow

        # Maintain exact bounds even if timestamps arrive out of order
        if packet.timestamp < flow.first_timestamp:
            flow.first_timestamp = packet.timestamp
        if packet.timestamp > flow.last_timestamp:
            flow.last_timestamp = packet.timestamp

        flow.duration = max(0.0, flow.last_timestamp - flow.first_timestamp)

        # Directional packet and byte attribution
        # Check whether packet source matches Endpoint A
        is_a_to_b = (
            packet.src_ip == flow.endpoint_a_ip
            and packet.src_port == flow.endpoint_a_port
        )

        if is_a_to_b:
            flow.packets_a_to_b += 1
            flow.bytes_a_to_b += bytes_count
        else:
            flow.packets_b_to_a += 1
            flow.bytes_b_to_a += bytes_count

        flow.total_packets += 1
        flow.total_bytes += bytes_count

        # TCP flag accounting
        if packet.tcp_flags:
            # Break compound flags (e.g., 'SA', 'FA', 'PA') into individual flag tallies
            flag_chars = {
                "S": "SYN",
                "A": "ACK",
                "F": "FIN",
                "R": "RST",
                "P": "PSH",
                "U": "URG",
                "E": "ECE",
                "C": "CWR",
            }
            for char, name in flag_chars.items():
                if char in packet.tcp_flags:
                    flow.tcp_flag_counts[name] = flow.tcp_flag_counts.get(name, 0) + 1

        # Track associated DNS queries
        if packet.dns_query and packet.dns_query not in flow.dns_queries:
            flow.dns_queries.append(packet.dns_query)

        return flow

    def get_flows(self) -> List[FlowRecord]:
        """Return all aggregated flows sorted by total packet volume descending."""
        return sorted(self._flows.values(), key=lambda f: f.total_packets, reverse=True)

    def expire_before(self, timestamp: float) -> int:
        """Remove flows inactive before timestamp and return the number removed."""
        stale = [key for key, flow in self._flows.items() if flow.last_timestamp < timestamp]
        for key in stale:
            del self._flows[key]
        return len(stale)

    def retain_most_recent(self, limit: int) -> int:
        """Bound table size by evicting flows with the oldest last-seen time."""
        if limit < 1:
            raise ValueError("Flow retention limit must be positive")
        excess = len(self._flows) - limit
        if excess <= 0:
            return 0
        oldest = sorted(self._flows, key=lambda key: self._flows[key].last_timestamp)[:excess]
        for key in oldest:
            del self._flows[key]
        return excess

    @property
    def flow_count(self) -> int:
        """Total number of distinct bidirectional flows."""
        return len(self._flows)


def aggregate_flows(packets: Iterable[PacketRecord]) -> List[FlowRecord]:
    """Convenience helper to aggregate an iterable of PacketRecords into FlowRecords.

    Args:
        packets: Iterable of PacketRecords.

    Returns:
        List of aggregated FlowRecords.
    """
    aggregator = FlowAggregator()
    for pkt in packets:
        aggregator.add_packet(pkt)
    return aggregator.get_flows()
