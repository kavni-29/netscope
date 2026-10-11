"""NetScope reporting and export engine.

Generates tabular CSV exports for flows, endpoints, alerts, and packets,
structured JSON exports for programmatic integration, and comprehensive
human-readable Markdown analysis reports.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from netscope.config import DetectionConfig
from netscope.exceptions import ExportError
from netscope.models import AlertRecord, AnalysisSummary, FlowRecord, PacketRecord
from netscope.statistics import EndpointMetric, StatisticsReport


def export_flows_csv(flows: List[FlowRecord], file_path: str | Path) -> Path:
    """Export bidirectional flow summaries to a CSV file."""
    path = Path(file_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "flow_id",
                "protocol",
                "endpoint_a_ip",
                "endpoint_a_port",
                "endpoint_b_ip",
                "endpoint_b_port",
                "packets_a_to_b",
                "packets_b_to_a",
                "bytes_a_to_b",
                "bytes_b_to_a",
                "total_packets",
                "total_bytes",
                "duration_seconds",
                "first_timestamp",
                "last_timestamp",
                "syn_count",
                "ack_count",
                "fin_count",
                "rst_count",
                "dns_queries",
            ])
            for flow in flows:
                syn_c = flow.tcp_flag_counts.get("SYN", 0)
                ack_c = flow.tcp_flag_counts.get("ACK", 0)
                fin_c = flow.tcp_flag_counts.get("FIN", 0)
                rst_c = flow.tcp_flag_counts.get("RST", 0)
                dns_str = "; ".join(flow.dns_queries) if flow.dns_queries else ""

                writer.writerow([
                    flow.flow_id,
                    flow.protocol,
                    flow.endpoint_a_ip,
                    flow.endpoint_a_port if flow.endpoint_a_port is not None else "",
                    flow.endpoint_b_ip,
                    flow.endpoint_b_port if flow.endpoint_b_port is not None else "",
                    flow.packets_a_to_b,
                    flow.packets_b_to_a,
                    flow.bytes_a_to_b,
                    flow.bytes_b_to_a,
                    flow.total_packets,
                    flow.total_bytes,
                    round(flow.duration, 4),
                    f"{flow.first_timestamp:.6f}",
                    f"{flow.last_timestamp:.6f}",
                    syn_c,
                    ack_c,
                    fin_c,
                    rst_c,
                    dns_str,
                ])
        return path
    except Exception as e:
        raise ExportError(f"Failed exporting flows CSV to {file_path}: {e}") from e


def export_alerts_csv(alerts: List[AlertRecord], file_path: str | Path) -> Path:
    """Export anomaly detection alerts to a CSV file."""
    path = Path(file_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "alert_id",
                "rule_id",
                "rule_name",
                "severity",
                "endpoint",
                "time_window",
                "observed_value",
                "threshold",
                "explanation",
                "evidence_summary",
            ])
            for alert in alerts:
                writer.writerow([
                    alert.alert_id,
                    alert.rule_id,
                    alert.rule_name,
                    alert.severity,
                    alert.endpoint,
                    alert.time_window,
                    str(alert.observed_value),
                    str(alert.threshold),
                    alert.explanation,
                    alert.evidence_summary,
                ])
        return path
    except Exception as e:
        raise ExportError(f"Failed exporting alerts CSV to {file_path}: {e}") from e


def export_endpoints_csv(endpoints: Dict[str, EndpointMetric], file_path: str | Path) -> Path:
    """Export endpoint traffic metrics to a CSV file."""
    path = Path(file_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "endpoint",
                "packets_sent",
                "packets_received",
                "bytes_sent",
                "bytes_received",
                "total_packets",
                "total_bytes",
                "distinct_dest_ports",
            ])
            for ep_metric in sorted(endpoints.values(), key=lambda e: e.total_packets, reverse=True):
                writer.writerow([
                    ep_metric.endpoint,
                    ep_metric.packets_sent,
                    ep_metric.packets_received,
                    ep_metric.bytes_sent,
                    ep_metric.bytes_received,
                    ep_metric.total_packets,
                    ep_metric.total_bytes,
                    ep_metric.distinct_dest_ports,
                ])
        return path
    except Exception as e:
        raise ExportError(f"Failed exporting endpoints CSV to {file_path}: {e}") from e


def export_packets_csv(packets: List[PacketRecord], file_path: str | Path) -> Path:
    """Export packet-level metadata to a CSV file."""
    path = Path(file_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "index",
                "timestamp",
                "datetime_utc",
                "src_ip",
                "dst_ip",
                "protocol",
                "src_port",
                "dst_port",
                "length",
                "wire_length",
                "tcp_flags",
                "dns_query",
                "dns_qtype",
                "parsing_status",
            ])
            for p in packets:
                writer.writerow([
                    p.index,
                    f"{p.timestamp:.6f}",
                    p.datetime_str,
                    p.src_ip or "",
                    p.dst_ip or "",
                    p.protocol,
                    p.src_port if p.src_port is not None else "",
                    p.dst_port if p.dst_port is not None else "",
                    p.length,
                    p.wire_length,
                    p.tcp_flags or "",
                    p.dns_query or "",
                    p.dns_qtype or "",
                    p.parsing_status,
                ])
        return path
    except Exception as e:
        raise ExportError(f"Failed exporting packets CSV to {file_path}: {e}") from e


def export_json(
    summary: AnalysisSummary,
    stats: StatisticsReport,
    flows: List[FlowRecord],
    alerts: List[AlertRecord],
    config: DetectionConfig,
    file_path: str | Path,
) -> Path:
    """Export complete analysis report to a structured JSON document."""
    path = Path(file_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "metadata": {
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "generator": "NetScope 1.0.0",
                "capture_file": summary.capture_file,
                "file_size_bytes": summary.file_size_bytes,
            },
            "summary": summary.to_dict(),
            "configuration": config.to_dict(),
            "protocols": {p: m.to_dict() for p, m in stats.protocols.items()},
            "packet_sizes": stats.packet_sizes.to_dict(),
            "top_endpoints": {
                "top_sources": [e.to_dict() for e in stats.top_sources],
                "top_destinations": [e.to_dict() for e in stats.top_destinations],
                "top_talkers_by_bytes": [e.to_dict() for e in stats.top_talkers_by_bytes],
            },
            "traffic_concentration": {
                "top1_percent": stats.traffic_concentration_top1_pct,
                "top3_percent": stats.traffic_concentration_top3_pct,
                "top5_percent": stats.traffic_concentration_top5_pct,
            },
            "time_series": [b.to_dict() for b in stats.time_series],
            "flows": [
                {
                    "flow_id": f.flow_id,
                    "protocol": f.protocol,
                    "endpoint_a": f.endpoint_a_str,
                    "endpoint_b": f.endpoint_b_str,
                    "packets_a_to_b": f.packets_a_to_b,
                    "packets_b_to_a": f.packets_b_to_a,
                    "bytes_a_to_b": f.bytes_a_to_b,
                    "bytes_b_to_a": f.bytes_b_to_a,
                    "total_packets": f.total_packets,
                    "total_bytes": f.total_bytes,
                    "duration_sec": round(f.duration, 4),
                    "tcp_flags": f.tcp_flag_counts,
                    "dns_queries": f.dns_queries,
                }
                for f in flows
            ],
            "alerts": [a.to_dict() for a in alerts],
            "defensive_security_notice": (
                "NetScope is an offline defensive analysis tool. Anomaly indicators signify "
                "statistical deviations or traffic patterns requiring triage; they do not constitute "
                "conclusive evidence of hostile intrusion."
            ),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path
    except Exception as e:
        raise ExportError(f"Failed exporting JSON report to {file_path}: {e}") from e


def generate_markdown_report(
    summary: AnalysisSummary,
    stats: StatisticsReport,
    flows: List[FlowRecord],
    alerts: List[AlertRecord],
    config: DetectionConfig,
) -> str:
    """Generate a comprehensive human-readable Markdown analysis report."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: List[str] = [
        "# NetScope — Network Traffic Analysis Report",
        f"**Generated:** {now_str}  ",
        f"**Target Capture:** `{summary.capture_file}` ({summary.file_size_bytes:,} bytes)  ",
        f"**Analysis Runtime:** {summary.analysis_duration_seconds:.2f} seconds  ",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total Packets Processed | **{summary.packets_processed:,}** |",
        f"| Packets Skipped / Errors | **{summary.packets_skipped + summary.packets_partial:,}** |",
        f"| Total Observed Bytes | **{summary.total_bytes:,} B** ({summary.total_bytes / (1024*1024):.2f} MB) |",
        f"| Capture Duration | **{summary.capture_duration_seconds:.2f} seconds** |",
        f"| Distinct Endpoints | **{summary.distinct_endpoints:,}** |",
        f"| Bidirectional Flows Identified | **{summary.identified_flows:,}** |",
        f"| Distinct Protocols | **{len(summary.protocols_observed)}** |",
        f"| Anomaly Alerts Triggered | **{summary.alerts_generated}** |",
        "",
        "---",
        "",
        "## 2. Protocol Distribution",
        "",
        "| Protocol | Packet Count | Packet Share | Byte Volume | Byte Share |",
        "|---|---|---|---|---|",
    ]

    for proto, m in sorted(stats.protocols.items(), key=lambda x: x[1].packet_count, reverse=True):
        lines.append(
            f"| `{proto}` | {m.packet_count:,} | {m.packet_percentage:.1f}% | {m.byte_count:,} B | {m.byte_percentage:.1f}% |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Packet Size Characteristics",
        "",
        "| Statistic | Value (Bytes) |",
        "|---|---|",
        f"| Minimum Length | {stats.packet_sizes.min_length} B |",
        f"| Maximum Length | {stats.packet_sizes.max_length} B |",
        f"| Mean Length | {stats.packet_sizes.mean_length:.1f} B |",
        f"| Median Length | {stats.packet_sizes.median_length:.1f} B |",
        f"| 25th Percentile | {stats.packet_sizes.percentile_25:.1f} B |",
        f"| 75th Percentile | {stats.packet_sizes.percentile_75:.1f} B |",
        f"| 95th Percentile | {stats.packet_sizes.percentile_95:.1f} B |",
        f"| Standard Deviation | {stats.packet_sizes.std_dev:.1f} B |",
        "",
        "### Frame Size Binned Distribution",
        "",
        "| Bin Range | Packet Count | Share |",
        "|---|---|---|",
    ])

    total_pkts = stats.total_packets or 1
    for bin_name, count in stats.packet_sizes.length_bins.items():
        share = count / total_pkts * 100.0
        lines.append(f"| {bin_name} | {count:,} | {share:.1f}% |")

    lines.extend([
        "",
        "---",
        "",
        "## 4. Endpoint Profiles & Traffic Concentration",
        "",
        f"- **Top 1 Endpoint Concentration:** {stats.traffic_concentration_top1_pct:.1f}% of total packets",
        f"- **Top 3 Endpoints Concentration:** {stats.traffic_concentration_top3_pct:.1f}% of total packets",
        f"- **Top 5 Endpoints Concentration:** {stats.traffic_concentration_top5_pct:.1f}% of total packets",
        "",
        "### Top Talkers (Combined Volume)",
        "",
        "| Endpoint IP | Packets Sent | Packets Recv | Total Bytes | Distinct Dst Ports |",
        "|---|---|---|---|---|",
    ])

    for ep in stats.top_talkers_by_bytes[:8]:
        lines.append(
            f"| `{ep.endpoint}` | {ep.packets_sent:,} | {ep.packets_received:,} | {ep.total_bytes:,} B | {ep.distinct_dest_ports} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 5. Bidirectional Flows Summary (Top 10 by Volume)",
        "",
        "| Flow Identifier | Protocol | A -> B Pkts | B -> A Pkts | Total Bytes | Duration |",
        "|---|---|---|---|---|---|",
    ])

    for f in flows[:10]:
        lines.append(
            f"| `{f.flow_id}` | {f.protocol} | {f.packets_a_to_b:,} | {f.packets_b_to_a:,} | {f.total_bytes:,} B | {f.duration:.2f}s |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 6. Explainable Anomaly Detection Findings",
        "",
    ])

    if not alerts:
        lines.append("*No anomaly indicators exceeded configured detection thresholds.*")
    else:
        lines.extend([
            "| ID | Severity | Rule Name | Endpoint | Observed vs Threshold | Explanation |",
            "|---|---|---|---|---|---|",
        ])
        for a in alerts:
            lines.append(
                f"| `{a.alert_id}` | **{a.severity}** | {a.rule_name} | `{a.endpoint}` | `{a.observed_value}` (Lim: `{a.threshold}`) | {a.explanation} |"
            )

        lines.extend([
            "",
            "### Detailed Evidence Breakdown",
            "",
        ])
        for a in alerts:
            lines.extend([
                f"#### [{a.severity}] {a.alert_id}: {a.rule_name}",
                f"- **Target / Scope:** `{a.endpoint}`",
                f"- **Time Window:** {a.time_window}",
                f"- **Observed Value:** {a.observed_value}",
                f"- **Configured Threshold:** {a.threshold}",
                f"- **Evidence Summary:** {a.evidence_summary}",
                f"- **Explanation:** {a.explanation}",
                "",
            ])

    lines.extend([
        "---",
        "",
        "## 7. Active Detection Configuration",
        "",
        "```json",
        json.dumps(config.to_dict(), indent=2),
        "```",
        "",
        "---",
        "",
        "## 8. Defensive Security Scope & Analytical Limitations",
        "",
        "- **Metadata vs Payload:** NetScope inspects packet headers and flow timing. Transport Layer Security (TLS) and application encryption prevent payload inspection; encrypted application content is neither decrypted nor inferred.",
        "- **Flow Grouping vs State Reconstruction:** NetScope groups packets into bidirectional flows. It does not perform full TCP stack emulation, connection state reconstruction, or retransmission tracking.",
        "- **Explainable Indicators vs Definitive Attribution:** Anomaly rules identify traffic that departs from expected baselines or matches scanning heuristics. High volume, destination port diversity, and high SYN ratios can be caused by legitimate applications, network drops, or asymmetric routing.",
    ])

    return "\n".join(lines)


def export_markdown_report(
    summary: AnalysisSummary,
    stats: StatisticsReport,
    flows: List[FlowRecord],
    alerts: List[AlertRecord],
    config: DetectionConfig,
    file_path: str | Path,
) -> Path:
    """Generate and write human-readable Markdown analysis report to file."""
    path = Path(file_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = generate_markdown_report(summary, stats, flows, alerts, config)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path
    except Exception as e:
        raise ExportError(f"Failed exporting Markdown report to {file_path}: {e}") from e
