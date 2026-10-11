"""NetScope Command-Line Interface (CLI).

A feature-rich, standalone terminal utility for offline packet inspection,
bidirectional flow aggregation, statistical profiling, and explainable
anomaly detection. Supports scriptable execution, subcommands, and reports.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional

from netscope.config import DetectionConfig
from netscope.detectors import DetectionEngine
from netscope.exceptions import ConfigurationError, InvalidCaptureError, NetScopeError
from netscope.flows import aggregate_flows
from netscope.models import AlertRecord, AnalysisSummary, FlowRecord, PacketRecord
from netscope.parser import parse_capture, stream_packets
from netscope.reporting import (
    export_alerts_csv,
    export_endpoints_csv,
    export_flows_csv,
    export_json,
    export_markdown_report,
    export_packets_csv,
)
from netscope.statistics import StatisticsReport, calculate_statistics
from netscope.visualisation import save_all_charts

__version__ = "1.0.0"

# ANSI styling helpers (disabled when redirected or on unsupported terminals)
USE_COLOR = sys.stdout.isatty()


def _c(text: str, color_code: str) -> str:
    """Format string with ANSI escape code if color is enabled."""
    return f"\033[{color_code}m{text}\033[0m" if USE_COLOR else text


def bold(text: str) -> str:
    return _c(text, "1")


def cyan(text: str) -> str:
    return _c(text, "36")


def green(text: str) -> str:
    return _c(text, "32")


def yellow(text: str) -> str:
    return _c(text, "33")


def red(text: str) -> str:
    return _c(text, "31")


def setup_logging(verbose: bool) -> None:
    """Configure console logging level and format."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def print_banner() -> None:
    """Print clean ASCII header banner."""
    print(cyan("=" * 76))
    print(bold("   NetScope — Network Traffic Analyzer & Explainable Anomaly Detection   "))
    print(cyan("=" * 76))


def print_terminal_summary(
    summary: AnalysisSummary,
    stats: StatisticsReport,
    flows: List[FlowRecord],
    alerts: List[AlertRecord],
) -> None:
    """Print clean, formatted terminal summary tables."""
    print(f"\n{bold(cyan('[+] CAPTURE SUMMARY'))}")
    print("-" * 76)
    print(f"  Target Capture      : {summary.capture_file}")
    print(f"  File Size           : {summary.file_size_bytes:,} bytes")
    print(f"  Packets Processed   : {green(f'{summary.packets_processed:,}')}")
    print(f"  Packets Skipped     : {summary.packets_skipped + summary.packets_partial:,}")
    print(f"  Total Volume        : {summary.total_bytes:,} bytes ({summary.total_bytes / (1024*1024):.2f} MB)")
    print(f"  Capture Duration    : {summary.capture_duration_seconds:.2f} seconds")
    print(f"  Distinct Endpoints  : {summary.distinct_endpoints:,}")
    print(f"  Identified Flows    : {summary.identified_flows:,}")
    print(f"  Analysis Runtime    : {summary.analysis_duration_seconds:.3f} seconds")

    print(f"\n{bold(cyan('[+] PROTOCOL DISTRIBUTION'))}")
    print("-" * 76)
    print(f"  {'Protocol':<12} {'Packets':>10} {'Share %':>10} {'Volume (Bytes)':>18} {'Share %':>10}")
    print("  " + "-" * 66)
    for proto, m in sorted(stats.protocols.items(), key=lambda x: x[1].packet_count, reverse=True):
        print(f"  {proto:<12} {m.packet_count:>10,} {m.packet_percentage:>9.1f}% {m.byte_count:>18,} {m.byte_percentage:>9.1f}%")

    print(f"\n{bold(cyan('[+] TOP COMMUNICATING ENDPOINTS'))}")
    print("-" * 76)
    print(f"  {'Endpoint IP':<22} {'Sent Pkts':>10} {'Recv Pkts':>10} {'Total Bytes':>16} {'Dst Ports':>10}")
    print("  " + "-" * 72)
    for ep in stats.top_talkers_by_bytes[:6]:
        print(f"  {ep.endpoint:<22} {ep.packets_sent:>10,} {ep.packets_received:>10,} {ep.total_bytes:>16,} {ep.distinct_dest_ports:>10}")

    print(f"\n{bold(cyan('[+] BIDIRECTIONAL FLOWS (TOP 5)'))}")
    print("-" * 76)
    for idx, f in enumerate(flows[:5], 1):
        print(f"  {idx}. [{f.protocol}] {bold(f.endpoint_a_str)} <-> {bold(f.endpoint_b_str)}")
        print(f"     Packets: {f.total_packets:,} (A->B: {f.packets_a_to_b}, B->A: {f.packets_b_to_a}) | Bytes: {f.total_bytes:,} | Duration: {f.duration:.2f}s")

    alert_count_str = red(str(len(alerts))) if alerts else green("0")
    print(f"\n{bold(cyan(f'[+] ANOMALY DETECTION ALERTS ({alert_count_str} Triggered)'))}")
    print("-" * 76)
    if not alerts:
        print(f"  {green('[OK]')} No anomaly indicators exceeded configured detection thresholds.")
    else:
        for a in alerts:
            sev_badge = red(f"[{a.severity}]") if a.severity in ("HIGH", "CRITICAL") else yellow(f"[{a.severity}]")
            print(f"  * {sev_badge} {bold(a.alert_id)}: {a.rule_name}")
            print(f"    Scope    : {a.endpoint} ({a.time_window})")
            print(f"    Observed : {bold(str(a.observed_value))}  (Threshold: {a.threshold})")
            print(f"    Evidence : {a.evidence_summary}")
    print(cyan("=" * 76) + "\n")


def print_packet_inspection(capture_path: Path, limit: int = 50) -> None:
    """Print sequential stream of packet headers to stdout (similar to tshark)."""
    print_banner()
    print(f"[i] Streaming packet inspection for {bold(str(capture_path))} (Limit: {limit} packets)...\n")
    print(f"{'#':<5} {'Time (s)':<12} {'Proto':<8} {'Source':<26} {'Destination':<26} {'Len':<6} {'Flags / Info'}")
    print("-" * 100)

    count = 0
    for pkt in stream_packets(capture_path, max_packets=limit):
        count += 1
        src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else (pkt.src_ip or "-")
        dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else (pkt.dst_ip or "-")
        info = pkt.tcp_flags or (f"DNS: {pkt.dns_query}" if pkt.dns_query else "-")
        print(f"{pkt.index:<5} {pkt.timestamp:<12.6f} {pkt.protocol:<8} {src:<26} {dst:<26} {pkt.wire_length:<6} {info}")

    print("-" * 100)
    print(f"[+] Displayed {count} packets.\n")


def print_flows_table(capture_path: Path, top: int = 20) -> None:
    """Print detailed tabular view of top bidirectional flows."""
    print_banner()
    print(f"[i] Extracting flows from {bold(str(capture_path))} (Top {top})...\n")
    packets, _ = parse_capture(capture_path)
    flows = aggregate_flows(packets)

    print(f"{'Proto':<8} {'Endpoint A':<26} {'Endpoint B':<26} {'A->B':>6} {'B->A':>6} {'Total':>7} {'Bytes':>12} {'Dur (s)':>8}")
    print("-" * 104)
    for f in flows[:top]:
        print(f"{f.protocol:<8} {f.endpoint_a_str:<26} {f.endpoint_b_str:<26} {f.packets_a_to_b:>6} {f.packets_b_to_a:>6} {f.total_packets:>7} {f.total_bytes:>12,} {f.duration:>8.2f}")
    print("-" * 104)
    print(f"[+] Total distinct bidirectional flows: {len(flows)}\n")


def print_alerts_view(capture_path: Path, config: Optional[DetectionConfig] = None) -> None:
    """Print detailed view of all anomaly alerts with evidence."""
    print_banner()
    summary, stats, flows, alerts = run_analysis_pipeline(capture_path, config=config)

    print(f"\n[+] ANOMALY DETECTION RESULTS ({len(alerts)} Alerts Triggered)")
    print("=" * 76)
    if not alerts:
        print(green("  [OK] No anomaly rules triggered on this capture."))
        return

    for a in alerts:
        sev = red(f"[{a.severity}]") if a.severity in ("HIGH", "CRITICAL") else yellow(f"[{a.severity}]")
        print(f"\n{sev} {bold(a.alert_id)} — {a.rule_name}")
        print(f"  Target Endpoint  : {bold(a.endpoint)}")
        print(f"  Time Window      : {a.time_window}")
        print(f"  Observed Value   : {green(str(a.observed_value))}")
        print(f"  Config Threshold : {a.threshold}")
        print(f"  Explanation      : {a.explanation}")
        print(f"  Evidence Summary : {a.evidence_summary}")
        if a.supporting_metadata.get("false_positive_context"):
            print(f"  False-Pos Context: {a.supporting_metadata['false_positive_context']}")
        print("-" * 76)


def run_analysis_pipeline(
    capture_path: str | Path,
    config: Optional[DetectionConfig] = None,
    max_packets: Optional[int] = None,
) -> tuple[AnalysisSummary, StatisticsReport, List[FlowRecord], List[AlertRecord]]:
    """Execute the core analysis pipeline shared by CLI and GUI."""
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


def build_arg_parser() -> argparse.ArgumentParser:
    """Build command-line argument parser supporting subcommands and direct flags."""
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope — Network Traffic Analyzer & Explainable Anomaly Detection System",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Subcommand: demo
    sub_demo = subparsers.add_parser("demo", help="Generate and run analysis on synthetic demonstration PCAP.")
    sub_demo.add_argument("-o", "--output", dest="output_dir", default="reports/demo", help="Output directory for reports.")
    sub_demo.add_argument("--charts", action="store_true", default=True, help="Generate visual chart PNGs.")

    # Subcommand: inspect
    sub_inspect = subparsers.add_parser("inspect", help="Stream packet headers sequentially to terminal.")
    sub_inspect.add_argument("file", help="Path to PCAP capture file.")
    sub_inspect.add_argument("--limit", type=int, default=50, help="Maximum packets to display (default: 50).")

    # Subcommand: flows
    sub_flows = subparsers.add_parser("flows", help="Display bidirectional network flows.")
    sub_flows.add_argument("file", help="Path to PCAP capture file.")
    sub_flows.add_argument("--top", type=int, default=20, help="Number of flows to display (default: 20).")

    # Subcommand: alerts
    sub_alerts = subparsers.add_parser("alerts", help="Display only explainable anomaly detection alerts.")
    sub_alerts.add_argument("file", help="Path to PCAP capture file.")
    sub_alerts.add_argument("-c", "--config", dest="config_file", help="Optional JSON config file.")

    # Subcommand: gui
    subparsers.add_parser("gui", help="Launch interactive desktop Graphical User Interface.")

    # Subcommand: version
    subparsers.add_parser("version", help="Print NetScope version information.")

    # Root flags (direct / backward compatible execution)
    parser.add_argument("input_pos", nargs="?", help="Path to input PCAP or PCAPNG capture file (positional).")
    parser.add_argument("-i", "--input", dest="input_file", help="Path to input PCAP or PCAPNG capture file.")
    parser.add_argument("-o", "--output", dest="output_dir", help="Output directory to save generated reports and exports.")
    parser.add_argument("-c", "--config", dest="config_file", help="Path to JSON configuration file overriding detection thresholds.")
    parser.add_argument("-f", "--format", dest="export_format", choices=["all", "csv", "json", "md", "none"], default="all", help="Export format (default: all).")
    parser.add_argument("--charts", action="store_true", help="Generate and save Matplotlib chart images in output directory.")
    parser.add_argument("--limit", type=int, dest="max_packets", help="Optional safety limit on maximum packets to process.")
    parser.add_argument("--demo", action="store_true", help="Run demonstration analysis on synthetic PCAP.")
    parser.add_argument("--gui", action="store_true", help="Launch the interactive desktop Graphical User Interface.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed debug logging.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress banner and non-essential progress output.")

    return parser


def main(args: Optional[list[str]] = None) -> int:
    """CLI entry point. Returns status code (0 for success, non-zero for error)."""
    raw_args = list(args if args is not None else sys.argv[1:])

    # Smart routing: if first arg is a file or not a subcommand/flag, treat as --input
    known_commands = {"demo", "inspect", "flows", "alerts", "gui", "version", "help", "-h", "--help"}
    if raw_args and not raw_args[0].startswith("-") and raw_args[0] not in known_commands:
        raw_args = ["--input", raw_args[0]] + raw_args[1:]

    parser = build_arg_parser()
    parsed_args = parser.parse_args(raw_args)

    # Handle 'version' subcommand
    if parsed_args.command == "version":
        print(f"NetScope version {__version__} (Python {sys.version.split()[0]} on {sys.platform})")
        return 0

    # Handle 'gui' subcommand or --gui flag
    if parsed_args.command == "gui" or parsed_args.gui:
        try:
            from netscope.gui import launch_gui
            launch_gui()
            return 0
        except Exception as e:
            print(f"Error launching GUI: {e}", file=sys.stderr)
            return 2

    # Handle 'demo' subcommand or --demo flag
    if parsed_args.command == "demo" or parsed_args.demo:
        demo_pcap = Path("samples") / "synthetic_demo.pcap"
        if not demo_pcap.is_file():
            print("[i] Generating synthetic demo PCAP fixture...")
            from samples.generate_sample_pcap import generate_synthetic_capture
            demo_pcap = generate_synthetic_capture(demo_pcap)

        out_dir = Path(getattr(parsed_args, "output_dir", None) or "reports/demo")
        print_banner()
        print(f"[i] Running demonstration analysis on {demo_pcap} ...")
        summary, stats, flows, alerts = run_analysis_pipeline(demo_pcap)
        print_terminal_summary(summary, stats, flows, alerts)

        out_dir.mkdir(parents=True, exist_ok=True)
        export_flows_csv(flows, out_dir / "flows.csv")
        export_alerts_csv(alerts, out_dir / "alerts.csv")
        export_endpoints_csv(stats.endpoints, out_dir / "endpoints.csv")
        export_json(summary, stats, flows, alerts, DetectionConfig(), out_dir / "report.json")
        export_markdown_report(summary, stats, flows, alerts, DetectionConfig(), out_dir / "report.md")
        save_all_charts(stats, alerts, out_dir / "charts")
        print(f"[+] Demo reports & charts saved to {out_dir.resolve()}\n")
        return 0

    # Handle 'inspect' subcommand
    if parsed_args.command == "inspect":
        target_file = Path(parsed_args.file)
        if not target_file.is_file():
            print(f"Error: Capture file not found: {target_file}", file=sys.stderr)
            return 1
        print_packet_inspection(target_file, limit=parsed_args.limit)
        return 0

    # Handle 'flows' subcommand
    if parsed_args.command == "flows":
        target_file = Path(parsed_args.file)
        if not target_file.is_file():
            print(f"Error: Capture file not found: {target_file}", file=sys.stderr)
            return 1
        print_flows_table(target_file, top=parsed_args.top)
        return 0

    # Handle 'alerts' subcommand
    if parsed_args.command == "alerts":
        target_file = Path(parsed_args.file)
        if not target_file.is_file():
            print(f"Error: Capture file not found: {target_file}", file=sys.stderr)
            return 1
        cfg = DetectionConfig.load_json(parsed_args.config_file) if parsed_args.config_file else None
        print_alerts_view(target_file, config=cfg)
        return 0

    # Determine input capture file (from positional argument or -i / --input flag)
    input_file_str = parsed_args.input_file or parsed_args.input_pos

    if not input_file_str:
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
        input_path = Path(input_file_str)
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
