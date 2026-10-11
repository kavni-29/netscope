"""NetScope data visualisation engine.

Generates Matplotlib charts for protocol distribution, traffic time series,
top communicating endpoints, packet size distributions, and anomaly alert summaries.
Decoupled from both GUI and CLI presentation logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend safe for headless CLI and Tk embedding
import matplotlib.pyplot as plt
from matplotlib.figure import Figure

from netscope.models import AlertRecord
from netscope.statistics import StatisticsReport

# Styling theme colors
PALETTE = {
    "primary": "#1f77b4",
    "secondary": "#2ca02c",
    "warning": "#ff7f0e",
    "danger": "#d62728",
    "purple": "#9467bd",
    "gray": "#7f7f7f",
    "light_gray": "#e0e0e0",
    "dark": "#2b2b2b",
}


def plot_protocol_distribution(stats: StatisticsReport) -> Figure:
    """Create a pie chart depicting packet share by protocol."""
    fig, ax = plt.subplots(figsize=(6, 4.5), dpi=100)

    if not stats.protocols:
        ax.text(0.5, 0.5, "No protocol data available", ha="center", va="center")
        ax.axis("off")
        return fig

    protocols = list(stats.protocols.keys())
    counts = [m.packet_count for m in stats.protocols.values()]

    colors = [
        PALETTE["primary"],
        PALETTE["secondary"],
        PALETTE["warning"],
        PALETTE["danger"],
        PALETTE["purple"],
        PALETTE["gray"],
    ]
    ax.pie(
        counts,
        labels=protocols,
        autopct="%1.1f%%",
        startangle=140,
        colors=colors[: len(protocols)],
        wedgeprops=dict(edgecolor="w", width=0.6),  # Donut style
    )
    ax.set_title("Traffic Share by Protocol", fontsize=12, fontweight="bold", pad=15)
    fig.tight_layout()
    return fig


def plot_traffic_over_time(stats: StatisticsReport) -> Figure:
    """Create a time series chart of packet counts and byte volume over capture intervals."""
    fig, ax1 = plt.subplots(figsize=(7, 4.5), dpi=100)

    if not stats.time_series:
        ax1.text(0.5, 0.5, "No time-series data available", ha="center", va="center")
        ax1.axis("off")
        return fig

    times = [b.relative_start_sec for b in stats.time_series]
    pkts = [b.packet_count for b in stats.time_series]
    bytes_kb = [b.byte_count / 1024.0 for b in stats.time_series]

    color_pkts = PALETTE["primary"]
    color_bytes = PALETTE["warning"]

    ax1.set_xlabel("Elapsed Time (seconds)", fontsize=10)
    ax1.set_ylabel("Packets / Interval", color=color_pkts, fontsize=10)
    line1 = ax1.plot(times, pkts, color=color_pkts, marker="o", markersize=3, label="Packets", linewidth=1.5)
    ax1.tick_params(axis="y", labelcolor=color_pkts)
    ax1.grid(True, linestyle="--", alpha=0.5)

    ax2 = ax1.twinx()
    ax2.set_ylabel("Volume (KB) / Interval", color=color_bytes, fontsize=10)
    line2 = ax2.plot(times, bytes_kb, color=color_bytes, linestyle="--", label="Volume (KB)", linewidth=1.5)
    ax2.tick_params(axis="y", labelcolor=color_bytes)

    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="upper right", framealpha=0.8)

    ax1.set_title("Traffic Volume Over Time", fontsize=12, fontweight="bold")
    fig.tight_layout()
    return fig


def plot_top_endpoints(stats: StatisticsReport) -> Figure:
    """Create a horizontal bar chart of top communicating endpoints by packet count."""
    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=100)

    top_talkers = stats.top_talkers_by_bytes[:8]
    if not top_talkers:
        ax.text(0.5, 0.5, "No endpoint data available", ha="center", va="center")
        ax.axis("off")
        return fig

    endpoints = [e.endpoint for e in reversed(top_talkers)]
    packets_sent = [e.packets_sent for e in reversed(top_talkers)]
    packets_recv = [e.packets_received for e in reversed(top_talkers)]

    y_pos = range(len(endpoints))
    ax.barh(y_pos, packets_sent, color=PALETTE["primary"], label="Packets Sent", alpha=0.85)
    ax.barh(y_pos, packets_recv, left=packets_sent, color=PALETTE["secondary"], label="Packets Received", alpha=0.85)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(endpoints, fontsize=9)
    ax.set_xlabel("Packet Count", fontsize=10)
    ax.set_title("Top 8 Communicating Endpoints", fontsize=12, fontweight="bold")
    ax.legend(loc="lower right", framealpha=0.8)
    ax.grid(axis="x", linestyle="--", alpha=0.5)
    fig.tight_layout()
    return fig


def plot_packet_size_distribution(stats: StatisticsReport) -> Figure:
    """Create a bar chart of packet lengths across standard frame bins."""
    fig, ax = plt.subplots(figsize=(6.5, 4.5), dpi=100)

    bins = stats.packet_sizes.length_bins
    if not bins or sum(bins.values()) == 0:
        ax.text(0.5, 0.5, "No packet size data available", ha="center", va="center")
        ax.axis("off")
        return fig

    categories = list(bins.keys())
    counts = list(bins.values())

    bars = ax.bar(categories, counts, color=PALETTE["purple"], alpha=0.85, edgecolor="none")
    ax.set_xlabel("Frame Size Range", fontsize=10)
    ax.set_ylabel("Packet Count", fontsize=10)
    ax.set_title("Packet Length Binned Distribution", fontsize=12, fontweight="bold")
    ax.tick_params(axis="x", rotation=30, labelsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    # Annotate bar counts
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.annotate(
                f"{h}",
                xy=(bar.get_x() + bar.get_width() / 2, h),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=8,
            )

    fig.tight_layout()
    return fig


def plot_alerts_summary(alerts: List[AlertRecord]) -> Figure:
    """Create a chart showing distribution of anomaly alerts by rule and severity."""
    fig, ax = plt.subplots(figsize=(6.5, 4.5), dpi=100)

    if not alerts:
        ax.text(0.5, 0.5, "No anomaly alerts triggered", ha="center", va="center", color=PALETTE["secondary"], fontsize=11)
        ax.axis("off")
        return fig

    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for a in alerts:
        severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

    sevs = [s for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] if severity_counts[s] > 0]
    counts = [severity_counts[s] for s in sevs]
    colors = {
        "LOW": PALETTE["secondary"],
        "MEDIUM": PALETTE["warning"],
        "HIGH": PALETTE["danger"],
        "CRITICAL": "#800000",
    }
    bar_colors = [colors.get(s, PALETTE["gray"]) for s in sevs]

    bars = ax.bar(sevs, counts, color=bar_colors, alpha=0.85)
    ax.set_ylabel("Alert Count", fontsize=10)
    ax.set_title("Anomaly Alerts by Severity", fontsize=12, fontweight="bold")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    for bar in bars:
        h = bar.get_height()
        ax.annotate(
            f"{h}",
            xy=(bar.get_x() + bar.get_width() / 2, h),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=9,
            fontweight="bold",
        )

    fig.tight_layout()
    return fig


def save_all_charts(
    stats: StatisticsReport,
    alerts: List[AlertRecord],
    output_dir: str | Path,
) -> List[Path]:
    """Generate and save all charts as high-resolution PNGs to the target directory."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    saved: List[Path] = []

    chart_funcs = [
        ("protocol_distribution.png", plot_protocol_distribution(stats)),
        ("traffic_over_time.png", plot_traffic_over_time(stats)),
        ("top_endpoints.png", plot_top_endpoints(stats)),
        ("packet_sizes.png", plot_packet_size_distribution(stats)),
        ("alerts_summary.png", plot_alerts_summary(alerts)),
    ]

    for fname, fig in chart_funcs:
        p = out_path / fname
        fig.savefig(p, dpi=150)
        plt.close(fig)
        saved.append(p)

    return saved
