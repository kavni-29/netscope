"""NetScope Command-Line Interface (CLI).

Provides scriptable, terminal-based execution of the network traffic analysis
engine without opening the GUI. Generates terminal summaries, exports reports,
and produces visual charts.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Optional

from netscope.config import DetectionConfig
from netscope.detectors import DetectionEngine
from netscope.exceptions import ConfigurationError, InvalidCaptureError, NetScopeError
from netscope.flows import aggregate_flows
from netscope.models import AnalysisSummary
from netscope.parser import parse_capture
from netscope.reporting import (
    export_alerts_csv,
    export_endpoints_csv,
    export_flows_csv,
    export_json,
    export_markdown_report,
    export_packets_csv,
)
from netscope.statistics import calculate_statistics
from netscope.visualisation import save_all_charts


def setup_logging(verbose: bool) -> None:
    """Configure console logging level and format."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def print_banner() -> None:
    """Print ASCII header banner."""
    print("=" * 72)
    print("   NetScope — Network Traffic Analyzer & Explainable Anomaly Detection   ")
    print("=" * 72)


def print_terminal_summary(
    summary: AnalysisSummary,
    stats,
    flows,
    alerts,
) -> None:
    """Print clean, formatted terminal summary tables."""
    print("\n[+] CAPTURE SUMMARY")
    print("-" * 72)
    print(f"  Target Capture      : {summary.capture_file}")
    print(f"  File Size           : {summary.file_size_bytes:,} bytes")
    print(f"  Packets Processed   : {summary.packets_processed:,}")
    print(f"  Packets Skipped     : {summary.packets_skipped + summary.packets_partial:,}")
    print(f"  Total Volume        : {summary.total_bytes:,} bytes ({summary.total_bytes / (1024*1024):.2f} MB)")
    print(f"  Capture Duration    : {summary.capture_duration_seconds:.2f} seconds")
    print(f"  Distinct Endpoints  : {summary.distinct_endpoints:,}")
    print(f"  Identified Flows    : {summary.identified_flows:,}")
    print(f"  Analysis Runtime    : {summary.analysis_duration_seconds:.3f} seconds")

    print("\n[+] PROTOCOL DISTRIBUTION")
    print("-" * 72)
    print(f"  {'Protocol':<12} {'Packets':>10} {'Share %':>10} {'Volume (Bytes)':>16} {'Share %':>10}")
    print("  " + "-" * 62)
    for proto, m in sorted(stats.protocols.items(), key=lambda x: x[1].packet_count, reverse=True):
        print(f"  {proto:<12} {m.packet_count:>10,} {m.packet_percentage:>9.1f}% {m.byte_count:>16,} {m.byte_percentage:>9.1f}%")

    print("\n[+] TOP COMMUNICATING ENDPOINTS")
    print("-" * 72)
    print(f"  {'Endpoint IP':<22} {'Sent Pkts':>10} {'Recv Pkts':>10} {'Total Bytes':>14} {'Dst Ports':>10}")
    print("  " + "-" * 68)
    for ep in stats.top_talkers_by_bytes[:5]:
        print(f"  {ep.endpoint:<22} {ep.packets_sent:>10,} {ep.packets_received:>10,} {ep.total_bytes:>14,} {ep.distinct_dest_ports:>10}")

    print("\n[+] BIDIRECTIONAL FLOWS (TOP 5)")
    print("-" * 72)
    for idx, f in enumerate(flows[:5], 1):
        print(f"  {idx}. [{f.protocol}] {f.endpoint_a_str} <-> {f.endpoint_b_str}")
        print(f"     Packets: {f.total_packets:,} (A->B: {f.packets_a_to_b}, B->A: {f.packets_b_to_a}) | Bytes: {f.total_bytes:,} | Duration: {f.duration:.2f}s")

    print(f"\n[+] ANOMALY DETECTION ALERTS ({len(alerts)} Triggered)")
    print("-" * 72)
    if not alerts:
        print("  [OK] No anomaly indicators exceeded configured detection thresholds.")
    else:
        for a in alerts:
            print(f"  * [{a.severity}] {a.alert_id}: {a.rule_name}")
            print(f"    Scope    : {a.endpoint} ({a.time_window})")
            print(f"    Observed : {a.observed_value}  (Threshold: {a.threshold})")
            print(f"    Evidence : {a.evidence_summary}")
    print("=" * 72 + "\n")


def build_arg_parser() -> argparse.ArgumentParser:
    """Build command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope — Network Traffic Analyzer & Explainable Anomaly Detection System",
    )
    parser.add_argument(
        "-i", "--input",
        dest="input_file",
        help="Path to input PCAP or PCAPNG capture file.",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_dir",
        help="Output directory to save generated reports and exports.",
    )
    parser.add_argument(
        "-c", "--config",
        dest="config_file",
        help="Path to JSON configuration file overriding detection thresholds.",
    )
    parser.add_argument(
        "-f", "--format",
        dest="export_format",
        choices=["all", "csv", "json", "md", "none"],
        default="all",
        help="Export format (default: all).",
    )
    parser.add_argument(
        "--charts",
        action="store_true",
        help="Generate and save Matplotlib chart images in output directory.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        dest="max_packets",
        help="Optional safety limit on maximum packets to process.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the interactive desktop Graphical User Interface.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable detailed debug logging.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and non-essential progress output.",
    )
    return parser


def run_analysis_pipeline(
    capture_path: str | Path,
    config: Optional[DetectionConfig] = None,
    max_packets: Optional[int] = None,
) -> tuple[AnalysisSummary, object, list, list]:
    """Execute the core analysis pipeline shared by CLI and GUI.

    Returns:
        (summary, stats, flows, alerts)
    """
    cfg = config or DetectionConfig()
    cfg.validate()

    start_wall = time.perf_counter()
    packets, metrics = parse_capture(capture_path, max_packets=max_packets or cfg.max_packets_safety_limit)
    flows = aggregate_flows(packets)
    stats = calculate_statistics(packets, flows, interval_sec=cfg.time_bucket_interval_sec)

    detector = DetectionEngine(config=cfg)
    alerts = detector.run(packets, flows, stats)
    runtime = time.perf_counter() - start_wall

    distinct_eps = len(stats.endpoints)
    proto_obs = {p: m.packet_count for p, m in stats.protocols.items()}

    summary = AnalysisSummary(
        capture_file=str(capture_path),
        file_size_bytes=metrics.file_size_bytes,
        packets_processed=metrics.parsed_ok,
        packets_skipped=metrics.parsed_error,
        packets_partial=metrics.parsed_partial,
        total_bytes=metrics.total_bytes,
        distinct_endpoints=distinct_eps,
        identified_flows=len(flows),
        protocols_observed=proto_obs,
        alerts_generated=len(alerts),
        analysis_duration_seconds=runtime,
        capture_start_time=stats.capture_start_ts,
        capture_end_time=stats.capture_end_ts,
        capture_duration_seconds=stats.capture_duration_sec,
    )

    return summary, stats, flows, alerts


def main(args: Optional[list[str]] = None) -> int:
    """CLI entry point. Returns status code (0 for success, non-zero for error)."""
    parser = build_arg_parser()
    parsed_args = parser.parse_args(args)

    if parsed_args.gui:
        try:
            from netscope.gui import launch_gui
            launch_gui()
            return 0
        except Exception as e:
            print(f"Error launching GUI: {e}", file=sys.stderr)
            return 2

    if not parsed_args.input_file:
        parser.print_help()
        print("\nError: --input capture file is required when not running with --gui.", file=sys.stderr)
        return 1

    setup_logging(parsed_args.verbose)

    if not parsed_args.quiet:
        print_banner()

    # Load configuration
    try:
        if parsed_args.config_file:
            config = DetectionConfig.load_json(parsed_args.config_file)
            if not parsed_args.quiet:
                print(f"[i] Loaded detection configuration from {parsed_args.config_file}")
        else:
            config = DetectionConfig()
    except (ConfigurationError, Exception) as e:
        print(f"Configuration Error: {e}", file=sys.stderr)
        return 1

    # Execute analysis pipeline
    try:
        input_path = Path(parsed_args.input_file)
        if not parsed_args.quiet:
            print(f"[i] Processing capture: {input_path} ...")

        summary, stats, flows, alerts = run_analysis_pipeline(
            capture_path=input_path,
            config=config,
            max_packets=parsed_args.max_packets,
        )

        if not parsed_args.quiet:
            print_terminal_summary(summary, stats, flows, alerts)

        # Handle exports
        if parsed_args.output_dir:
            out_dir = Path(parsed_args.output_dir)
        else:
            out_dir = Path("reports") / input_path.stem

        fmt = parsed_args.export_format
        if fmt != "none":
            out_dir.mkdir(parents=True, exist_ok=True)
            if not parsed_args.quiet:
                print(f"[i] Exporting analysis artifacts to: {out_dir.resolve()}")

            if fmt in ("all", "csv"):
                export_flows_csv(flows, out_dir / "flows.csv")
                export_alerts_csv(alerts, out_dir / "alerts.csv")
                export_endpoints_csv(stats.endpoints, out_dir / "endpoints.csv")
                # export_packets_csv(packets, out_dir / "packets.csv")

            if fmt in ("all", "json"):
                export_json(summary, stats, flows, alerts, config, out_dir / "report.json")

            if fmt in ("all", "md"):
                export_markdown_report(summary, stats, flows, alerts, config, out_dir / "report.md")

        if parsed_args.charts:
            chart_paths = save_all_charts(stats, alerts, out_dir / "charts")
            if not parsed_args.quiet:
                print(f"[i] Saved {len(chart_paths)} visualization charts in {out_dir / 'charts'}")

        if not parsed_args.quiet:
            print("[+] Analysis completed successfully.")
        return 0

    except InvalidCaptureError as e:
        print(f"Invalid Capture Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        logging.getLogger(__name__).exception("Analysis failure")
        print(f"Fatal Analysis Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
