"""NetScope reporting and export engine.

Generates tabular CSV exports for flows, endpoints, alerts, and packets,
structured JSON exports for programmatic integration, and comprehensive
human-readable Markdown analysis reports.
"""

from __future__ import annotations

import csv
import json
import html
import io
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from netscope.config import DetectionConfig
from netscope.exceptions import ExportError
from netscope.models import AlertRecord, AnalysisSummary, FlowRecord, PacketRecord
from netscope.statistics import EndpointMetric, StatisticsReport


def export_pdf_report(
    summary: AnalysisSummary,
    stats: StatisticsReport,
    flows: List[FlowRecord],
    alerts: List[AlertRecord],
    config: DetectionConfig,
    file_path: str | Path,
    *,
    mode: str = "offline",
    interface: Optional[str] = None,
) -> Path:
    """Write a paginated PDF analysis report with reusable NetScope charts."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, KeepTogether
    from netscope.visualisation import save_all_charts

    path = Path(file_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], textColor=colors.HexColor("#174a72"), alignment=TA_CENTER, spaceAfter=8))
        styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=7.5, leading=9, wordWrap="CJK"))
        styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], textColor=colors.HexColor("#174a72"), spaceBefore=10, spaceAfter=6, keepWithNext=1))

        def safe(value: object) -> str:
            return html.escape(str(value if value not in (None, "") else "—"))

        def table(rows, widths, repeat=1):
            result = Table(rows, colWidths=widths, repeatRows=repeat, hAlign="LEFT")
            result.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#174a72")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEADING", (0, 0), (-1, -1), 10),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#cbd5df")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            return result

        def footer(canvas, doc):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor("#cbd5df"))
            canvas.line(18 * mm, 14 * mm, doc.pagesize[0] - 18 * mm, 14 * mm)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#52616b"))
            canvas.drawString(18 * mm, 9 * mm, f"NetScope • Defensive traffic analysis • {generated}")
            canvas.drawRightString(doc.pagesize[0] - 18 * mm, 9 * mm, f"Page {doc.page}")
            canvas.restoreState()

        doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=17 * mm, bottomMargin=20 * mm, pageCompression=0)
        doc.title = "NetScope Network Traffic Analysis Report"
        doc.author = "NetScope"
        story = [Paragraph("NetScope", styles["ReportTitle"]), Paragraph("Network Traffic Analysis Report", styles["Heading1"]),
                 Paragraph(f"Generated {generated} | Mode: {safe(mode.title())} analysis", styles["Normal"]),
                 Paragraph(f"Source: {safe(summary.capture_file)}" + (f" | Interface: {safe(interface)}" if interface else ""), styles["Normal"]), Spacer(1, 8),
                 Paragraph("Executive Summary", styles["Section"]),
                 Paragraph("This report summarizes observed packet metadata and rule-based indicators. An alert is a heuristic requiring context and is not proof of malicious activity.", styles["BodyText"]), Spacer(1, 6)]
        summary_rows = [["Measure", "Observed"], ["Packets analysed", f"{summary.packets_processed:,}"], ["Bytes analysed", f"{stats.total_bytes:,}"],
                        ["Unique IP endpoints", f"{len(stats.endpoints):,}"], ["Bidirectional flows", f"{len(flows):,}"],
                        ["Anomaly indicators", f"{len(alerts):,}"], ["Capture interval", f"{stats.capture_duration_sec:.2f} s"],
                        ["Analysis runtime", f"{summary.analysis_duration_seconds:.3f} s"]]
        story += [table(summary_rows, [65 * mm, 100 * mm]), Paragraph("Traffic Overview", styles["Section"])]
        if stats.protocols:
            proto_rows = [["Protocol", "Packets", "Packet share", "Bytes", "Byte share"]]
            proto_rows.extend([[safe(m.protocol), f"{m.packet_count:,}", f"{m.packet_percentage:.1f}%", f"{m.byte_count:,}", f"{m.byte_percentage:.1f}%"] for m in stats.protocols.values()])
            story.append(table(proto_rows, [32 * mm, 27 * mm, 29 * mm, 35 * mm, 30 * mm]))
        if stats.top_talkers_by_bytes:
            story += [Spacer(1, 8), Paragraph("Top Communicating Endpoints", styles["Heading3"])]
            rows = [["Endpoint", "Packets", "Bytes", "Distinct destination ports"]]
            rows.extend([[safe(e.endpoint), f"{e.total_packets:,}", f"{e.total_bytes:,}", str(e.distinct_dest_ports)] for e in stats.top_talkers_by_bytes[:10]])
            story.append(table(rows, [53 * mm, 28 * mm, 36 * mm, 40 * mm]))
        ps = stats.packet_sizes
        story += [Spacer(1, 8), Paragraph("Packet sizes (wire length)", styles["Heading3"]),
                  Paragraph(f"Count {ps.count:,} · min {ps.min_length:,} B · max {ps.max_length:,} B · mean {ps.mean_length:.1f} B · median {ps.median_length:.1f} B", styles["BodyText"])]

        if alerts:
            story.append(Paragraph("Anomaly Findings", styles["Section"]))
            alert_rows = [["Severity / rule", "Endpoint", "Observed / threshold", "Evidence and explanation"]]
            alert_rows.extend([[Paragraph(f"<b>{safe(a.severity)}</b><br/>{safe(a.rule_name)}", styles["SmallCell"]),
                                Paragraph(safe(a.endpoint), styles["SmallCell"]),
                                Paragraph(f"{safe(a.observed_value)}<br/>Threshold: {safe(a.threshold)}", styles["SmallCell"]),
                                Paragraph(f"{safe(a.evidence_summary)}<br/>{safe(a.explanation)}", styles["SmallCell"])] for a in alerts])
            story.append(table(alert_rows, [37 * mm, 34 * mm, 39 * mm, 48 * mm]))
        else:
            finding_text = "No packets were available for anomaly evaluation." if not stats.total_packets else "No configured detection threshold was exceeded in the analysed data."
            story += [Paragraph("Anomaly Findings", styles["Section"]), Paragraph(finding_text, styles["BodyText"])]

        if flows:
            story.append(Paragraph("Bidirectional Flows", styles["Section"]))
            rows = [["Protocol", "Endpoint A", "Endpoint B", "A-to-B / B-to-A packets", "Bytes", "Duration"]]
            rows.extend([[safe(f.protocol), Paragraph(safe(f.endpoint_a_str), styles["SmallCell"]), Paragraph(safe(f.endpoint_b_str), styles["SmallCell"]),
                          f"{f.packets_a_to_b:,} / {f.packets_b_to_a:,}", f"{f.total_bytes:,}", f"{f.duration:.2f} s"] for f in flows])
            story.append(table(rows, [18 * mm, 38 * mm, 38 * mm, 32 * mm, 23 * mm, 18 * mm]))

        if stats.endpoints:
            story.append(Paragraph("Endpoint Details", styles["Section"]))
            rows = [["Endpoint", "Sent", "Received", "Total bytes", "Destination ports"]]
            endpoint_rows = sorted(stats.endpoints.values(), key=lambda e: e.total_bytes, reverse=True)
            rows.extend([[Paragraph(safe(e.endpoint), styles["SmallCell"]), f"{e.packets_sent:,}", f"{e.packets_received:,}", f"{e.total_bytes:,}", str(e.distinct_dest_ports)] for e in endpoint_rows])
            story.append(table(rows, [47 * mm, 24 * mm, 27 * mm, 33 * mm, 36 * mm]))

        has_visual_data = bool(stats.protocols or stats.time_series or stats.endpoints or stats.packet_sizes.count or alerts)
        if has_visual_data:
            story.append(Paragraph("Traffic Visualisations", styles["Section"]))
            with tempfile.TemporaryDirectory(prefix="netscope-pdf-") as temp_dir:
                chart_paths = save_all_charts(stats, alerts, temp_dir)
                for chart_path in chart_paths:
                    chart = Image(io.BytesIO(chart_path.read_bytes()), width=165 * mm, height=90 * mm, kind="proportional")
                    story.append(KeepTogether([chart, Spacer(1, 5)]))

        story += [Paragraph("Methodology and Limitations", styles["Section"]),
                  Paragraph("NetScope aggregates packet metadata into canonical bidirectional flows and evaluates configurable deterministic rules for packet rates, destination-port diversity, TCP SYN ratios, volume deviations, traffic concentration, and repeated communication. Encryption limits application visibility; no payload decryption, full TCP state reconstruction, or attack attribution is performed. Benign workloads and network conditions can trigger indicators.", styles["BodyText"])]
        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        return path
    except Exception as exc:
        raise ExportError(f"Failed exporting PDF report to {file_path}: {exc}") from exc


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
