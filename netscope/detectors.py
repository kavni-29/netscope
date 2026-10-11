"""NetScope explainable anomaly detection engine.

Implements rule-based, deterministic, and fully configurable anomaly detection
rules for network traffic analysis. Each rule generates structured alerts containing
clear evidence, threshold comparisons, and false-positive context.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

import numpy as np

from netscope.config import DetectionConfig
from netscope.models import AlertRecord, FlowRecord, PacketRecord
from netscope.statistics import StatisticsReport


class BaseDetector(ABC):
    """Abstract base class for all explainable anomaly detection rules."""

    rule_id: str
    rule_name: str
    default_severity: str

    @abstractmethod
    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: StatisticsReport,
        config: DetectionConfig,
    ) -> List[AlertRecord]:
        """Evaluate rule criteria and return generated AlertRecords."""
        pass


class HighPacketRateDetector(BaseDetector):
    """Rule 1: Identifies endpoints exceeding packet rate threshold within a time window."""

    rule_id = "RULE_HIGH_PACKET_RATE"
    rule_name = "High Packet Rate Observation"
    default_severity = "MEDIUM"

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: StatisticsReport,
        config: DetectionConfig,
    ) -> List[AlertRecord]:
        alerts: List[AlertRecord] = []
        if not packets:
            return alerts

        window_sec = config.high_packet_rate_window_sec
        threshold = config.high_packet_rate_threshold
        policy = config.high_packet_rate_policy

        # Group timestamps by endpoint
        endpoint_timestamps: Dict[str, List[float]] = defaultdict(list)
        for p in packets:
            if p.timestamp <= 0:
                continue
            if p.src_ip:
                endpoint_timestamps[p.src_ip].append(p.timestamp)
            if policy == "both" and p.dst_ip and p.dst_ip != p.src_ip:
                endpoint_timestamps[p.dst_ip].append(p.timestamp)

        alert_idx = 1
        for ep, timestamps in endpoint_timestamps.items():
            if len(timestamps) <= threshold:
                continue

            timestamps.sort()
            # Sliding window count
            left = 0
            max_in_window = 0
            window_start_ts = timestamps[0]
            window_end_ts = timestamps[0]

            for right in range(len(timestamps)):
                while timestamps[right] - timestamps[left] > window_sec:
                    left += 1
                curr_count = right - left + 1
                if curr_count > max_in_window:
                    max_in_window = curr_count
                    window_start_ts = timestamps[left]
                    window_end_ts = timestamps[right]

            if max_in_window > threshold:
                severity = "HIGH" if max_in_window >= threshold * 2 else self.default_severity
                observed_rate = max_in_window / window_sec if window_sec > 0 else max_in_window
                alerts.append(
                    AlertRecord(
                        alert_id=f"ALT-RATE-{alert_idx:03d}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=severity,
                        endpoint=ep,
                        time_window=f"{window_sec:.1f}s [{window_start_ts:.3f} - {window_end_ts:.3f}]",
                        observed_value=f"{max_in_window} packets ({observed_rate:.1f} pkts/s)",
                        threshold=f">{threshold} packets / {window_sec:.1f}s",
                        explanation=(
                            f"Endpoint {ep} transmitted {max_in_window} packets within a "
                            f"{window_sec:.1f}s window, exceeding the configured threshold of {threshold} packets."
                        ),
                        evidence_summary=(
                            f"Peak packet count: {max_in_window} observed in window "
                            f"[{window_start_ts:.3f} - {window_end_ts:.3f}]. Policy: {policy}."
                        ),
                        supporting_metadata={
                            "endpoint": ep,
                            "window_seconds": window_sec,
                            "packet_count": max_in_window,
                            "rate_pkts_per_sec": round(observed_rate, 2),
                            "false_positive_context": (
                                "Legitimate bulk transfers, database replication, or file downloads "
                                "can routinely produce high packet rates without malice."
                            ),
                        },
                    )
                )
                alert_idx += 1

        return alerts


class PortDiversityDetector(BaseDetector):
    """Rule 2: Identifies source endpoints contacting an unusually high number of distinct destination ports."""

    rule_id = "RULE_PORT_DIVERSITY"
    rule_name = "Destination Port Diversity (Scan Heuristic)"
    default_severity = "MEDIUM"

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: StatisticsReport,
        config: DetectionConfig,
    ) -> List[AlertRecord]:
        alerts: List[AlertRecord] = []
        if not packets:
            return alerts

        window_sec = config.port_diversity_window_sec
        threshold = config.port_diversity_threshold

        # Organize by source IP: list of (timestamp, dst_port)
        src_port_events: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        for p in packets:
            if p.src_ip and p.dst_port is not None:
                src_port_events[p.src_ip].append((p.timestamp, p.dst_port))

        alert_idx = 1
        for src_ip, events in src_port_events.items():
            if len(events) <= threshold:
                continue

            events.sort(key=lambda x: x[0])
            # Sliding window over events
            left = 0
            max_unique_ports: Set[int] = set()
            win_start = events[0][0]
            win_end = events[0][0]

            for right in range(len(events)):
                while events[right][0] - events[left][0] > window_sec:
                    left += 1

                unique_in_window = {e[1] for e in events[left : right + 1]}
                if len(unique_in_window) > len(max_unique_ports):
                    max_unique_ports = unique_in_window
                    win_start = events[left][0]
                    win_end = events[right][0]

            if len(max_unique_ports) > threshold:
                severity = "HIGH" if len(max_unique_ports) >= threshold * 2 else self.default_severity
                sample_ports = sorted(list(max_unique_ports))[:10]
                alerts.append(
                    AlertRecord(
                        alert_id=f"ALT-PORT-{alert_idx:03d}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=severity,
                        endpoint=src_ip,
                        time_window=f"{window_sec:.1f}s [{win_start:.3f} - {win_end:.3f}]",
                        observed_value=f"{len(max_unique_ports)} distinct ports",
                        threshold=f">{threshold} distinct ports",
                        explanation=(
                            f"Suspicious indicator: Source {src_ip} contacted {len(max_unique_ports)} "
                            f"distinct destination ports within {window_sec:.1f}s, exceeding threshold of {threshold}."
                        ),
                        evidence_summary=(
                            f"Contacted {len(max_unique_ports)} distinct ports within window. "
                            f"Sample target ports: {sample_ports}."
                        ),
                        supporting_metadata={
                            "endpoint": src_ip,
                            "distinct_port_count": len(max_unique_ports),
                            "sample_ports": sample_ports,
                            "window_seconds": window_sec,
                            "false_positive_context": (
                                "Legitimate peer-to-peer applications, service discovery, web browsers "
                                "loading multi-origin assets, or network monitoring scanners may exhibit high port diversity."
                            ),
                        },
                    )
                )
                alert_idx += 1

        return alerts


class SynWithoutAckDetector(BaseDetector):
    """Rule 3: Identifies endpoints with a high ratio of TCP SYN packets without ACK."""

    rule_id = "RULE_SYN_WITHOUT_ACK"
    rule_name = "High TCP SYN Ratio Without ACK"
    default_severity = "MEDIUM"

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: StatisticsReport,
        config: DetectionConfig,
    ) -> List[AlertRecord]:
        alerts: List[AlertRecord] = []
        ratio_threshold = config.syn_ratio_threshold
        min_packets = config.syn_min_packets

        # Track per source IP: (total_tcp_packets, syn_no_ack_packets)
        tcp_counts: Dict[str, List[int]] = defaultdict(lambda: [0, 0])

        for p in packets:
            if p.protocol == "TCP" and p.src_ip and p.tcp_flags:
                flags = p.tcp_flags.upper()
                tcp_counts[p.src_ip][0] += 1
                # SYN set and ACK NOT set
                if "S" in flags and "A" not in flags:
                    tcp_counts[p.src_ip][1] += 1

        alert_idx = 1
        for src_ip, (total_tcp, syn_no_ack) in tcp_counts.items():
            if total_tcp < min_packets:
                continue

            ratio = syn_no_ack / total_tcp
            if ratio >= ratio_threshold:
                severity = "HIGH" if ratio >= 0.90 else self.default_severity
                alerts.append(
                    AlertRecord(
                        alert_id=f"ALT-SYN-{alert_idx:03d}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=severity,
                        endpoint=src_ip,
                        time_window="Capture Duration",
                        observed_value=f"{ratio:.1%} ({syn_no_ack}/{total_tcp} TCP packets)",
                        threshold=f">={ratio_threshold:.1%} (min {min_packets} packets)",
                        explanation=(
                            f"Suspicious indicator: Source {src_ip} sent {syn_no_ack} TCP SYN packets "
                            f"without ACK flag out of {total_tcp} total TCP packets ({ratio:.1%})."
                        ),
                        evidence_summary=(
                            f"TCP packets observed: {total_tcp}. SYN-without-ACK packets: {syn_no_ack}. "
                            f"Computed ratio: {ratio:.3f} >= threshold {ratio_threshold}."
                        ),
                        supporting_metadata={
                            "endpoint": src_ip,
                            "syn_without_ack_count": syn_no_ack,
                            "total_tcp_count": total_tcp,
                            "ratio": round(ratio, 4),
                            "false_positive_context": (
                                "A high SYN ratio does not prove an intrusion. Packet capture drops, "
                                "asymmetric routing where response ACKs travel via a different interface, "
                                "or connection attempts to unreachable servers can cause identical observations."
                            ),
                        },
                    )
                )
                alert_idx += 1

        return alerts


class VolumeDeviationDetector(BaseDetector):
    """Rule 4: Identifies intervals whose traffic volume deviates significantly from baseline."""

    rule_id = "RULE_VOLUME_DEVIATION"
    rule_name = "Traffic Volume Statistical Deviation"
    default_severity = "MEDIUM"

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: StatisticsReport,
        config: DetectionConfig,
    ) -> List[AlertRecord]:
        alerts: List[AlertRecord] = []
        buckets = stats.time_series
        min_intervals = config.volume_deviation_min_intervals
        z_threshold = config.volume_deviation_zscore

        if len(buckets) < min_intervals:
            return alerts

        byte_counts = np.array([b.byte_count for b in buckets], dtype=np.float64)
        mean_bytes = float(np.mean(byte_counts))
        std_bytes = float(np.std(byte_counts, ddof=1)) if len(byte_counts) > 1 else 0.0

        # Cannot calculate z-score if standard deviation is zero (zero variance)
        if std_bytes <= 0.0001:
            return alerts

        alert_idx = 1
        for b in buckets:
            # Leave-one-out or standard z-score
            z_score = (b.byte_count - mean_bytes) / std_bytes
            if z_score > z_threshold:
                severity = "HIGH" if z_score >= 4.0 else self.default_severity
                alerts.append(
                    AlertRecord(
                        alert_id=f"ALT-VOL-{alert_idx:03d}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=severity,
                        endpoint=f"Interval #{b.bucket_index}",
                        time_window=f"Interval #{b.bucket_index} [{b.relative_start_sec:.1f}s - {b.relative_end_sec:.1f}s]",
                        observed_value=f"{b.byte_count:,} bytes (Z-score: +{z_score:.2f})",
                        threshold=f"Z-score > +{z_threshold:.1f} (Mean: {mean_bytes:,.0f} B, Std: {std_bytes:,.0f} B)",
                        explanation=(
                            f"Traffic volume anomaly: Interval #{b.bucket_index} observed {b.byte_count:,} bytes, "
                            f"deviating by +{z_score:.2f} standard deviations from the capture baseline mean."
                        ),
                        evidence_summary=(
                            f"Interval observed: {b.byte_count} bytes, {b.packet_count} packets. "
                            f"Baseline mean: {mean_bytes:.1f} B, std: {std_bytes:.1f} B."
                        ),
                        supporting_metadata={
                            "bucket_index": b.bucket_index,
                            "interval_bytes": b.byte_count,
                            "interval_packets": b.packet_count,
                            "baseline_mean_bytes": round(mean_bytes, 2),
                            "baseline_std_bytes": round(std_bytes, 2),
                            "z_score": round(z_score, 3),
                            "false_positive_context": (
                                "Bursty legitimate traffic such as video streaming initialization, "
                                "large file transfers, or batch synchronization can trigger volume spikes."
                            ),
                        },
                    )
                )
                alert_idx += 1

        return alerts


class TrafficConcentrationDetector(BaseDetector):
    """Rule 5: Identifies unusually concentrated traffic involving a single endpoint."""

    rule_id = "RULE_TRAFFIC_CONCENTRATION"
    rule_name = "Endpoint Traffic Concentration"
    default_severity = "LOW"

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: StatisticsReport,
        config: DetectionConfig,
    ) -> List[AlertRecord]:
        alerts: List[AlertRecord] = []
        total_packets = stats.total_packets
        min_packets = config.traffic_concentration_min_packets
        threshold_ratio = config.traffic_concentration_threshold

        if total_packets < min_packets or not stats.endpoints:
            return alerts

        alert_idx = 1
        for ep, metric in stats.endpoints.items():
            ratio = metric.total_packets / total_packets
            if ratio >= threshold_ratio:
                severity = "MEDIUM" if ratio >= 0.80 else self.default_severity
                alerts.append(
                    AlertRecord(
                        alert_id=f"ALT-CONC-{alert_idx:03d}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=severity,
                        endpoint=ep,
                        time_window="Capture Duration",
                        observed_value=f"{ratio:.1%} ({metric.total_packets}/{total_packets} packets)",
                        threshold=f">={threshold_ratio:.1%} of capture volume",
                        explanation=(
                            f"Traffic concentration indicator: Endpoint {ep} accounted for {metric.total_packets} "
                            f"out of {total_packets} captured packets ({ratio:.1%})."
                        ),
                        evidence_summary=(
                            f"Endpoint total packets: {metric.total_packets}, bytes: {metric.total_bytes:,}. "
                            f"Ratio: {ratio:.3f} >= threshold {threshold_ratio}."
                        ),
                        supporting_metadata={
                            "endpoint": ep,
                            "endpoint_packets": metric.total_packets,
                            "endpoint_bytes": metric.total_bytes,
                            "total_capture_packets": total_packets,
                            "ratio": round(ratio, 4),
                            "false_positive_context": (
                                "High traffic concentration is expected for central servers, default gateways, "
                                "DNS resolvers, or when a capture isolates a specific client-server transaction."
                            ),
                        },
                    )
                )
                alert_idx += 1

        return alerts


class RepeatedCommunicationDetector(BaseDetector):
    """Rule 6: Identifies repetitive bursts between specific source and destination endpoints."""

    rule_id = "RULE_REPEATED_COMMUNICATION"
    rule_name = "Repeated Communication Pattern"
    default_severity = "LOW"

    def evaluate(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: StatisticsReport,
        config: DetectionConfig,
    ) -> List[AlertRecord]:
        alerts: List[AlertRecord] = []
        threshold = config.repeated_comm_threshold
        window_sec = config.repeated_comm_window_sec

        # Group by tuple: (src_ip, dst_ip, dst_port) -> list of timestamps
        tuples_ts: Dict[Tuple[str, str, Optional[int]], List[float]] = defaultdict(list)
        for p in packets:
            if p.src_ip and p.dst_ip:
                tuples_ts[(p.src_ip, p.dst_ip, p.dst_port)].append(p.timestamp)

        alert_idx = 1
        for (src_ip, dst_ip, dst_port), timestamps in tuples_ts.items():
            if len(timestamps) <= threshold:
                continue

            timestamps.sort()
            left = 0
            max_in_window = 0
            win_start = timestamps[0]
            win_end = timestamps[0]

            for right in range(len(timestamps)):
                while timestamps[right] - timestamps[left] > window_sec:
                    left += 1
                count = right - left + 1
                if count > max_in_window:
                    max_in_window = count
                    win_start = timestamps[left]
                    win_end = timestamps[right]

            if max_in_window > threshold:
                dst_port_str = f":{dst_port}" if dst_port is not None else ""
                endpoint_label = f"{src_ip} -> {dst_ip}{dst_port_str}"
                severity = "MEDIUM" if max_in_window >= threshold * 2 else self.default_severity

                alerts.append(
                    AlertRecord(
                        alert_id=f"ALT-REP-{alert_idx:03d}",
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=severity,
                        endpoint=endpoint_label,
                        time_window=f"{window_sec:.1f}s [{win_start:.3f} - {win_end:.3f}]",
                        observed_value=f"{max_in_window} repeated packets",
                        threshold=f">{threshold} packets / {window_sec:.1f}s",
                        explanation=(
                            f"Repetitive communication pattern: {endpoint_label} transmitted {max_in_window} "
                            f"packets within a {window_sec:.1f}s window."
                        ),
                        evidence_summary=(
                            f"Observed {max_in_window} packets to identical destination in "
                            f"{window_sec:.1f}s window."
                        ),
                        supporting_metadata={
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "destination_port": dst_port,
                            "burst_packet_count": max_in_window,
                            "window_seconds": window_sec,
                            "false_positive_context": (
                                "Application keep-alive pings, health checks, rapid API polling, "
                                "and NTP synchronization exhibit repeated communication patterns."
                            ),
                        },
                    )
                )
                alert_idx += 1

        return alerts


class DetectionEngine:
    """Orchestrates configurable explainable anomaly detection rules."""

    def __init__(self, config: Optional[DetectionConfig] = None) -> None:
        self.config = config or DetectionConfig()
        self.config.validate()
        self.detectors: List[BaseDetector] = [
            HighPacketRateDetector(),
            PortDiversityDetector(),
            SynWithoutAckDetector(),
            VolumeDeviationDetector(),
            TrafficConcentrationDetector(),
            RepeatedCommunicationDetector(),
        ]

    def run(
        self,
        packets: List[PacketRecord],
        flows: List[FlowRecord],
        stats: StatisticsReport,
    ) -> List[AlertRecord]:
        """Execute all configured detectors on the analyzed capture data."""
        all_alerts: List[AlertRecord] = []
        for detector in self.detectors:
            try:
                rule_alerts = detector.evaluate(packets, flows, stats, self.config)
                all_alerts.extend(rule_alerts)
            except Exception as e:
                # Log detector issue without terminating entire pipeline
                import logging
                logging.getLogger(__name__).error("Detector %s error: %s", detector.rule_id, e)

        # Sort alerts by severity priority: CRITICAL > HIGH > MEDIUM > LOW
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_alerts.sort(key=lambda a: (severity_rank.get(a.severity, 4), a.alert_id))
        return all_alerts
