"""Unit tests for NetScope reporting and export functions."""

import csv
import json
from pathlib import Path

from netscope.config import DetectionConfig
from netscope.flows import aggregate_flows
from netscope.models import AlertRecord, AnalysisSummary, PacketRecord
from netscope.reporting import (
    export_alerts_csv,
    export_endpoints_csv,
    export_flows_csv,
    export_json,
    export_markdown_report,
    export_packets_csv,
    export_pdf_report,
)
from netscope.statistics import calculate_statistics


def test_export_flows_csv(tmp_path: Path):
    """Test exporting flows to CSV with correct headers and values."""
    pkts = [
        PacketRecord.create(1, 100.0, "192.168.1.10", "10.0.0.1", "TCP", 50000, 80, length=120, tcp_flags="S"),
        PacketRecord.create(2, 101.0, "10.0.0.1", "192.168.1.10", "TCP", 80, 50000, length=150, tcp_flags="SA"),
    ]
    flows = aggregate_flows(pkts)
    csv_file = tmp_path / "exports" / "flows.csv"

    exported = export_flows_csv(flows, csv_file)
    assert exported.is_file()

    with open(exported, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 1
        r = rows[0]
        assert r["protocol"] == "TCP"
        assert r["total_packets"] == "2"
        assert r["total_bytes"] == "270"
        assert float(r["duration_seconds"]) == 1.0


def test_export_alerts_csv(tmp_path: Path):
    """Test exporting alert records with quotes, commas and special characters."""
    alerts = [
        AlertRecord(
            alert_id="ALT-001",
            rule_id="RULE_TEST",
            rule_name="Test, Rule (Quoted)",
            severity="HIGH",
            endpoint="10.0.0.1",
            time_window="10.0s [0.0 - 10.0]",
            observed_value="20 packets",
            threshold=">10 packets",
            explanation="Explanation with, commas and \"quotes\" safely formatted.",
            evidence_summary="Observed 20 packets: [1, 2, 3]",
        )
    ]
    csv_file = tmp_path / "alerts.csv"
    export_alerts_csv(alerts, csv_file)

    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["alert_id"] == "ALT-001"
        assert "quotes" in rows[0]["explanation"]


def test_export_json_valid_schema(tmp_path: Path):
    """Test JSON export structure and round-trip parsing."""
    pkts = [PacketRecord.create(1, 10.0, "1.1.1.1", "2.2.2.2", "TCP", 100, 200, length=60)]
    flows = aggregate_flows(pkts)
    stats = calculate_statistics(pkts)
    cfg = DetectionConfig()
    summary = AnalysisSummary(
        capture_file="dummy.pcap",
        file_size_bytes=1024,
        packets_processed=1,
        packets_skipped=0,
        packets_partial=0,
        total_bytes=60,
        distinct_endpoints=2,
        identified_flows=1,
        protocols_observed={"TCP": 1},
        alerts_generated=0,
        analysis_duration_seconds=0.01,
    )

    json_path = tmp_path / "sub" / "report.json"
    export_json(summary, stats, flows, [], cfg, json_path)
    assert json_path.is_file()

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["metadata"]["capture_file"] == "dummy.pcap"
    assert data["summary"]["packets_processed"] == 1
    assert "protocols" in data
    assert "flows" in data
    assert "alerts" in data


def test_export_markdown_report_content(tmp_path: Path):
    """Test human-readable Markdown report content and sections."""
    pkts = [PacketRecord.create(1, 10.0, "1.1.1.1", "2.2.2.2", "TCP", 100, 200, length=60)]
    flows = aggregate_flows(pkts)
    stats = calculate_statistics(pkts)
    cfg = DetectionConfig()
    summary = AnalysisSummary(
        capture_file="test.pcap",
        file_size_bytes=500,
        packets_processed=1,
        packets_skipped=0,
        packets_partial=0,
        total_bytes=60,
        distinct_endpoints=2,
        identified_flows=1,
        protocols_observed={"TCP": 1},
        alerts_generated=0,
        analysis_duration_seconds=0.02,
    )

    md_path = tmp_path / "report.md"
    export_markdown_report(summary, stats, flows, [], cfg, md_path)
    assert md_path.is_file()

    content = md_path.read_text(encoding="utf-8")
    assert "# NetScope — Network Traffic Analysis Report" in content
    assert "Executive Summary" in content
    assert "Protocol Distribution" in content
    assert "Defensive Security Scope" in content


def test_export_pdf_report_contains_report_content(tmp_path: Path):
    packets = [
        PacketRecord.create(1, 10.0, "10.0.0.1", "10.0.0.2", "TCP", 50000, 443, length=120),
        PacketRecord.create(2, 10.5, "10.0.0.2", "10.0.0.1", "TCP", 443, 50000, length=180),
    ]
    flows = aggregate_flows(packets)
    stats = calculate_statistics(packets, flows)
    summary = AnalysisSummary("capture.pcap", 300, 2, 0, 0, 300, 2, 1, {"TCP": 2}, 0, 0.02)
    path = export_pdf_report(summary, stats, flows, [], DetectionConfig(), tmp_path / "reports" / "report.pdf")
    payload = path.read_bytes()
    assert payload.startswith(b"%PDF-")
    assert b"Network Traffic Analysis Report" in payload
    assert b"Packets analysed" in payload
    assert b"capture.pcap" in payload
    assert b"10.0.0.1" in payload


def test_export_pdf_report_handles_empty_analysis(tmp_path: Path):
    stats = calculate_statistics([])
    summary = AnalysisSummary("empty.pcap", 0, 0, 0, 0, 0, 0, 0, {}, 0, 0.0)
    path = export_pdf_report(summary, stats, [], [], DetectionConfig(), tmp_path / "empty.pdf")
    payload = path.read_bytes()
    assert payload.startswith(b"%PDF-")
    assert b"No packets were available for anomaly evaluation" in payload
    assert b"Traffic Visualisations" not in payload


def test_export_pdf_report_paginates_long_flow_table(tmp_path: Path):
    packets = [PacketRecord.create(i, float(i), f"10.0.{i // 250}.{i % 250}", "192.0.2.1", "UDP", 2000 + i, 53, length=64) for i in range(1, 85)]
    flows = aggregate_flows(packets)
    stats = calculate_statistics(packets, flows)
    summary = AnalysisSummary("large.pcap", 84 * 64, 84, 0, 0, 84 * 64, 84, len(flows), {"UDP": 84}, 0, 0.1)
    payload = export_pdf_report(summary, stats, flows, [], DetectionConfig(), tmp_path / "large.pdf").read_bytes()
    assert payload.startswith(b"%PDF-")
    assert payload.count(b"Page ") >= 2


def test_export_pdf_report_wraps_output_errors(tmp_path: Path):
    from netscope.exceptions import ExportError
    import pytest

    stats = calculate_statistics([])
    summary = AnalysisSummary("empty.pcap", 0, 0, 0, 0, 0, 0, 0, {}, 0, 0.0)
    with pytest.raises(ExportError, match="Failed exporting PDF report"):
        export_pdf_report(summary, stats, [], [], DetectionConfig(), tmp_path)
