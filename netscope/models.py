"""NetScope data models.

Defines typed dataclasses and structures for packets, network flows,
anomaly detection alerts, and capture analysis summaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class PacketRecord:
    """Represents normalized metadata extracted from an individual captured packet."""

    index: int
    timestamp: float
    datetime_str: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int = 0
    wire_length: int = 0
    tcp_flags: Optional[str] = None
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    parsing_status: str = "OK"  # "OK", "PARTIAL", "ERROR"
    error_reason: Optional[str] = None

    @classmethod
    def create(
        cls,
        index: int,
        timestamp: float,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        protocol: str,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        length: int = 0,
        wire_length: Optional[int] = None,
        tcp_flags: Optional[str] = None,
        dns_query: Optional[str] = None,
        dns_qtype: Optional[str] = None,
        parsing_status: str = "OK",
        error_reason: Optional[str] = None,
    ) -> PacketRecord:
        """Factory method computing formatted UTC timestamp string."""
        try:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            dt_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
        except (ValueError, OSError, OverflowError):
            dt_str = "1970-01-01 00:00:00.000000"

        effective_wire_len = wire_length if wire_length is not None else length

        return cls(
            index=index,
            timestamp=timestamp,
            datetime_str=dt_str,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            wire_length=effective_wire_len,
            tcp_flags=tcp_flags,
            dns_query=dns_query,
            dns_qtype=dns_qtype,
            parsing_status=parsing_status,
            error_reason=error_reason,
        )


@dataclass(frozen=True)
class FlowKey:
    """Canonical bidirectional flow key.

    Independent of packet direction: (Endpoint1, Endpoint2) is deterministically
    ordered so that traffic from A to B and B to A map to the exact same flow key.
    """

    protocol: str
    endpoint_a: Tuple[str, Optional[int]]
    endpoint_b: Tuple[str, Optional[int]]

    @classmethod
    def build(
        cls,
        protocol: str,
        src_ip: Optional[str],
        src_port: Optional[int],
        dst_ip: Optional[str],
        dst_port: Optional[int],
    ) -> FlowKey:
        """Construct a deterministic bidirectional key."""
        ep1 = (src_ip or "0.0.0.0", src_port)
        ep2 = (dst_ip or "0.0.0.0", dst_port)

        # Lexicographical comparison for deterministic ordering:
        # compare (IP string, port if int else -1)
        sort_key_1 = (ep1[0], ep1[1] if ep1[1] is not None else -1)
        sort_key_2 = (ep2[0], ep2[1] if ep2[1] is not None else -1)

        if sort_key_1 <= sort_key_2:
            return cls(protocol=protocol.upper(), endpoint_a=ep1, endpoint_b=ep2)
        else:
            return cls(protocol=protocol.upper(), endpoint_a=ep2, endpoint_b=ep1)


@dataclass
class FlowRecord:
    """Aggregated bidirectional network flow record."""

    flow_id: str
    protocol: str
    endpoint_a_ip: str
    endpoint_a_port: Optional[int]
    endpoint_b_ip: str
    endpoint_b_port: Optional[int]
    first_timestamp: float
    last_timestamp: float
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    duration: float = 0.0
    tcp_flag_counts: Dict[str, int] = field(default_factory=dict)
    dns_queries: List[str] = field(default_factory=list)

    @property
    def endpoint_a_str(self) -> str:
        """Formatted string for Endpoint A."""
        if self.endpoint_a_port is not None:
            return f"{self.endpoint_a_ip}:{self.endpoint_a_port}"
        return self.endpoint_a_ip

    @property
    def endpoint_b_str(self) -> str:
        """Formatted string for Endpoint B."""
        if self.endpoint_b_port is not None:
            return f"{self.endpoint_b_ip}:{self.endpoint_b_port}"
        return self.endpoint_b_ip


@dataclass
class AlertRecord:
    """Structured, explainable anomaly detection record."""

    alert_id: str
    rule_id: str
    rule_name: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    endpoint: str
    time_window: str
    observed_value: Any
    threshold: Any
    explanation: str
    evidence_summary: str
    supporting_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to a serializable dictionary."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "time_window": self.time_window,
            "observed_value": self.observed_value,
            "threshold": self.threshold,
            "explanation": self.explanation,
            "evidence_summary": self.evidence_summary,
            "supporting_metadata": self.supporting_metadata,
        }


@dataclass
class AnalysisSummary:
    """Overall summary metrics for a processed capture."""

    capture_file: str
    file_size_bytes: int
    packets_processed: int
    packets_skipped: int
    packets_partial: int
    total_bytes: int
    distinct_endpoints: int
    identified_flows: int
    protocols_observed: Dict[str, int]
    alerts_generated: int
    analysis_duration_seconds: float
    capture_start_time: Optional[float] = None
    capture_end_time: Optional[float] = None
    capture_duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary."""
        return {
            "capture_file": self.capture_file,
            "file_size_bytes": self.file_size_bytes,
            "packets_processed": self.packets_processed,
            "packets_skipped": self.packets_skipped,
            "packets_partial": self.packets_partial,
            "total_bytes": self.total_bytes,
            "distinct_endpoints": self.distinct_endpoints,
            "identified_flows": self.identified_flows,
            "protocols_observed": self.protocols_observed,
            "alerts_generated": self.alerts_generated,
            "analysis_duration_seconds": round(self.analysis_duration_seconds, 4),
            "capture_start_time": self.capture_start_time,
            "capture_end_time": self.capture_end_time,
            "capture_duration_seconds": round(self.capture_duration_seconds, 4),
        }
