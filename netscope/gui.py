"""NetScope Desktop Graphical User Interface (GUI).

Professional Tkinter / ttk desktop application featuring multi-tab navigation,
asynchronous worker threading for non-blocking analysis, sortable treeviews,
master-detail alert inspection, embedded Matplotlib figures, and one-click exports.
"""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from netscope.cli import run_analysis_pipeline
from netscope.config import DetectionConfig
from netscope.models import AlertRecord, AnalysisSummary, FlowRecord
from netscope.reporting import (
    export_alerts_csv,
    export_endpoints_csv,
    export_flows_csv,
    export_json,
    export_markdown_report,
)
from netscope.statistics import EndpointMetric, StatisticsReport
from netscope.visualisation import (
    plot_alerts_summary,
    plot_packet_size_distribution,
    plot_protocol_distribution,
    plot_top_endpoints,
    plot_traffic_over_time,
)


class NetScopeGUI(tk.Tk):
    """Main NetScope desktop application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("NetScope — Network Traffic Analyzer")
        self.geometry("1150x760")
        self.minsize(950, 620)

        # Application state
        self.current_capture_path: Optional[Path] = None
        self.analysis_summary: Optional[AnalysisSummary] = None
        self.statistics_report: Optional[StatisticsReport] = None
        self.flows: List[FlowRecord] = []
        self.alerts: List[AlertRecord] = []
        self.config: DetectionConfig = DetectionConfig()
        self.msg_queue: queue.Queue = queue.Queue()
        self.is_analyzing = False

        self._configure_styles()
        self._build_ui()
        self._poll_queue()

    def _configure_styles(self) -> None:
        """Configure ttk widget styles and palette."""
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        # Clean color constants
        self.c_primary = "#1f4e79"
        self.c_secondary = "#2e75b6"
        self.c_bg = "#f4f6f9"
        self.c_card_bg = "#ffffff"
        self.c_text = "#2b2b2b"
        self.c_accent = "#d9534f"

        self.configure(bg=self.c_bg)

        self.style.configure(".", background=self.c_bg, foreground=self.c_text, font=("Segoe UI", 9))
        self.style.configure("TFrame", background=self.c_bg)
        self.style.configure("Header.TFrame", background=self.c_primary)
        self.style.configure("Card.TFrame", background=self.c_card_bg, relief="groove")

        self.style.configure(
            "TButton",
            font=("Segoe UI", 9, "bold"),
            padding=5,
        )
        self.style.configure(
            "Primary.TButton",
            font=("Segoe UI", 9, "bold"),
            foreground="#ffffff",
            background=self.c_secondary,
            padding=6,
        )
        self.style.map("Primary.TButton", background=[("active", self.c_primary)])

        self.style.configure(
            "Treeview",
            background="#ffffff",
            foreground="#2b2b2b",
            rowheight=24,
            fieldbackground="#ffffff",
            font=("Segoe UI", 9),
        )
        self.style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 9, "bold"),
            background="#e9ecef",
            foreground="#1f4e79",
            padding=4,
        )
        self.style.map("Treeview.Heading", background=[("active", "#d0d7de")])

        # Alert severity tags
        self.tag_colors = {
            "CRITICAL": "#ffcccc",
            "HIGH": "#ffe0cc",
            "MEDIUM": "#fff3cd",
            "LOW": "#e2e3e5",
        }

    def _build_ui(self) -> None:
        """Build top control bar, notebook tabs, and status footer."""
        # Top Header Bar
        header = ttk.Frame(self, style="Header.TFrame", padding=(15, 10))
        header.pack(fill="x", side="top")

        lbl_title = tk.Label(
            header,
            text="NetScope — Network Traffic Analyzer",
            font=("Segoe UI", 14, "bold"),
            fg="#ffffff",
            bg=self.c_primary,
        )
        lbl_title.pack(side="left")

        lbl_subtitle = tk.Label(
            header,
            text="Offline Packet & Flow Inspection with Explainable Anomaly Detection",
            font=("Segoe UI", 9, "italic"),
            fg="#d0e1fd",
            bg=self.c_primary,
        )
        lbl_subtitle.pack(side="left", padx=15)

        # File Intake Control Frame
        intake_frame = ttk.Frame(self, padding=(15, 10))
        intake_frame.pack(fill="x", side="top")

        ttk.Label(intake_frame, text="Capture File:").pack(side="left")
        self.ent_filepath = ttk.Entry(intake_frame, font=("Segoe UI", 9))
        self.ent_filepath.pack(side="left", fill="x", expand=True, padx=8)

        btn_browse = ttk.Button(intake_frame, text="Browse...", command=self._on_browse)
        btn_browse.pack(side="left", padx=4)

        self.btn_analyze = ttk.Button(
            intake_frame,
            text="Analyse Capture",
            style="Primary.TButton",
            command=self._on_analyze,
        )
        self.btn_analyze.pack(side="left", padx=6)

        self.progress_bar = ttk.Progressbar(intake_frame, mode="indeterminate", length=140)
        self.progress_bar.pack(side="left", padx=6)

        # Main Notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=5)

        # Tab Frames
        self.tab_overview = ttk.Frame(self.notebook, padding=10)
        self.tab_flows = ttk.Frame(self.notebook, padding=10)
        self.tab_endpoints = ttk.Frame(self.notebook, padding=10)
        self.tab_alerts = ttk.Frame(self.notebook, padding=10)
        self.tab_charts = ttk.Frame(self.notebook, padding=10)
        self.tab_export = ttk.Frame(self.notebook, padding=10)

        self.notebook.add(self.tab_overview, text=" Summary Overview ")
        self.notebook.add(self.tab_flows, text=" Bidirectional Flows ")
        self.notebook.add(self.tab_endpoints, text=" Endpoints Profile ")
        self.notebook.add(self.tab_alerts, text=" Anomaly Alerts ")
        self.notebook.add(self.tab_charts, text=" Visualisations ")
        self.notebook.add(self.tab_export, text=" Reports & Exports ")

        self._build_tab_overview()
        self._build_tab_flows()
        self._build_tab_endpoints()
        self._build_tab_alerts()
        self._build_tab_charts()
        self._build_tab_export()

        # Status Footer
        footer = ttk.Frame(self, padding=(15, 6))
        footer.pack(fill="x", side="bottom")

        self.lbl_status = ttk.Label(footer, text="Ready. Select a PCAP or PCAPNG file to begin.", font=("Segoe UI", 9))
        self.lbl_status.pack(side="left")

        self.lbl_runtime = ttk.Label(footer, text="", font=("Segoe UI", 9, "italic"))
        self.lbl_runtime.pack(side="right")

    # ---------------- TAB 1: OVERVIEW ----------------
    def _build_tab_overview(self) -> None:
        # Metric Cards Container
        cards_frame = ttk.Frame(self.tab_overview)
        cards_frame.pack(fill="x", pady=5)

        self.metric_cards: Dict[str, tk.Label] = {}
        card_defs = [
            ("Packets Processed", "0"),
            ("Observed Bytes", "0 B"),
            ("Distinct Endpoints", "0"),
            ("Identified Flows", "0"),
            ("Distinct Protocols", "0"),
            ("Anomaly Alerts", "0"),
        ]

        for idx, (title, default_val) in enumerate(card_defs):
            c = tk.Frame(cards_frame, bg=self.c_card_bg, relief="ridge", bd=1)
            c.grid(row=0, column=idx, padx=5, sticky="nsew")
            cards_frame.grid_columnconfigure(idx, weight=1)

            lbl_t = tk.Label(c, text=title, font=("Segoe UI", 8, "bold"), fg="#6c757d", bg=self.c_card_bg)
            lbl_t.pack(anchor="w", padx=8, pady=(6, 2))
            lbl_v = tk.Label(c, text=default_val, font=("Segoe UI", 14, "bold"), fg=self.c_primary, bg=self.c_card_bg)
            lbl_v.pack(anchor="w", padx=8, pady=(0, 6))
            self.metric_cards[title] = lbl_v

        # Capture Details & Protocols split
        split_frame = ttk.Frame(self.tab_overview)
        split_frame.pack(fill="both", expand=True, pady=10)
        split_frame.columnconfigure(0, weight=1)
        split_frame.columnconfigure(1, weight=1)

        # Left: Details Frame
        meta_group = ttk.LabelFrame(split_frame, text=" Capture Metadata ", padding=10)
        meta_group.grid(row=0, column=0, sticky="nsew", padx=5)

        self.txt_metadata = tk.Text(meta_group, wrap="word", height=12, font=("Consolas", 9), relief="solid", bd=1)
        self.txt_metadata.pack(fill="both", expand=True)
        self.txt_metadata.insert("1.0", "No capture analyzed yet.")
        self.txt_metadata.config(state="disabled")

        # Right: Protocols Table
        proto_group = ttk.LabelFrame(split_frame, text=" Protocols Breakdown ", padding=10)
        proto_group.grid(row=0, column=1, sticky="nsew", padx=5)

        cols = ("Protocol", "Packets", "Packet %", "Volume (Bytes)", "Byte %")
        self.tree_proto = ttk.Treeview(proto_group, columns=cols, show="headings", height=10)
        for c in cols:
            self.tree_proto.heading(c, text=c)
            self.tree_proto.column(c, width=80, anchor="center")
        self.tree_proto.column("Protocol", width=90, anchor="w")
        self.tree_proto.pack(fill="both", expand=True)

    # ---------------- TAB 2: FLOWS ----------------
    def _build_tab_flows(self) -> None:
        cols = ("Protocol", "Endpoint A", "Endpoint B", "A->B Pkts", "B->A Pkts", "Total Pkts", "Total Bytes", "Duration (s)")
        self.tree_flows = ttk.Treeview(self.tab_flows, columns=cols, show="headings")

        sb = ttk.Scrollbar(self.tab_flows, orient="vertical", command=self.tree_flows.yview)
        self.tree_flows.configure(yscrollcommand=sb.set)

        for col in cols:
            self.tree_flows.heading(col, text=col, command=lambda c=col: self._sort_treeview(self.tree_flows, c, False))
            self.tree_flows.column(col, width=110, anchor="center")
        self.tree_flows.column("Endpoint A", width=180, anchor="w")
        self.tree_flows.column("Endpoint B", width=180, anchor="w")

        self.tree_flows.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    # ---------------- TAB 3: ENDPOINTS ----------------
    def _build_tab_endpoints(self) -> None:
        cols = ("Endpoint IP", "Packets Sent", "Packets Recv", "Total Packets", "Total Bytes", "Distinct Dst Ports")
        self.tree_endpoints = ttk.Treeview(self.tab_endpoints, columns=cols, show="headings")

        sb = ttk.Scrollbar(self.tab_endpoints, orient="vertical", command=self.tree_endpoints.yview)
        self.tree_endpoints.configure(yscrollcommand=sb.set)

        for col in cols:
            self.tree_endpoints.heading(col, text=col, command=lambda c=col: self._sort_treeview(self.tree_endpoints, c, False))
            self.tree_endpoints.column(col, width=120, anchor="center")
        self.tree_endpoints.column("Endpoint IP", width=220, anchor="w")

        self.tree_endpoints.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    # ---------------- TAB 4: ALERTS ----------------
    def _build_tab_alerts(self) -> None:
        paned = ttk.PanedWindow(self.tab_alerts, orient="vertical")
        paned.pack(fill="both", expand=True)

        top_frame = ttk.Frame(paned)
        paned.add(top_frame, weight=3)

        cols = ("Severity", "Alert ID", "Rule Name", "Endpoint", "Observed Value", "Threshold")
        self.tree_alerts = ttk.Treeview(top_frame, columns=cols, show="headings")
        sb = ttk.Scrollbar(top_frame, orient="vertical", command=self.tree_alerts.yview)
        self.tree_alerts.configure(yscrollcommand=sb.set)

        for col in cols:
            self.tree_alerts.heading(col, text=col, command=lambda c=col: self._sort_treeview(self.tree_alerts, c, False))
            self.tree_alerts.column(col, width=130, anchor="w")
        self.tree_alerts.column("Severity", width=90, anchor="center")
        self.tree_alerts.column("Alert ID", width=100, anchor="center")

        self.tree_alerts.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.tree_alerts.bind("<<TreeviewSelect>>", self._on_alert_selected)

        # Bottom Detail Pane
        bottom_frame = ttk.LabelFrame(paned, text=" Alert Evidence & Explanation ", padding=8)
        paned.add(bottom_frame, weight=2)

        self.txt_alert_detail = tk.Text(bottom_frame, wrap="word", font=("Segoe UI", 9), relief="solid", bd=1)
        self.txt_alert_detail.pack(fill="both", expand=True)
        self.txt_alert_detail.insert("1.0", "Select an alert row above to inspect detailed evidence.")
        self.txt_alert_detail.config(state="disabled")

    def _on_alert_selected(self, event) -> None:
        selected_items = self.tree_alerts.selection()
        if not selected_items:
            return
        item_id = selected_items[0]
        vals = self.tree_alerts.item(item_id, "values")
        if not vals:
            return
        alert_id = vals[1]

        target = next((a for a in self.alerts if a.alert_id == alert_id), None)
        if not target:
            return

        detail_text = (
            f"Alert Identifier : {target.alert_id}\n"
            f"Rule Name        : {target.rule_name} ({target.rule_id})\n"
            f"Assigned Severity: {target.severity}\n"
            f"Target Endpoint  : {target.endpoint}\n"
            f"Observed Value   : {target.observed_value}\n"
            f"Config Threshold : {target.threshold}\n"
            f"Time Window      : {target.time_window}\n\n"
            f"[+] Explanation:\n{target.explanation}\n\n"
            f"[+] Evidence Summary:\n{target.evidence_summary}\n\n"
            f"[+] Defensive False-Positive Context:\n"
            f"{target.supporting_metadata.get('false_positive_context', 'Review network topology and client behaviour.')}\n"
        )

        self.txt_alert_detail.config(state="normal")
        self.txt_alert_detail.delete("1.0", "end")
        self.txt_alert_detail.insert("1.0", detail_text)
        self.txt_alert_detail.config(state="disabled")

    # ---------------- TAB 5: CHARTS ----------------
    def _build_tab_charts(self) -> None:
        ctrl_frame = ttk.Frame(self.tab_charts, padding=(0, 0, 0, 8))
        ctrl_frame.pack(fill="x", side="top")

        ttk.Label(ctrl_frame, text="Select Chart View:").pack(side="left", padx=5)
        self.chart_var = tk.StringVar(value="Protocol Distribution")
        chart_options = [
            "Protocol Distribution",
            "Traffic Volume Over Time",
            "Top Endpoints",
            "Packet Length Bins",
            "Alerts by Severity",
        ]
        self.cmb_charts = ttk.Combobox(ctrl_frame, textvariable=self.chart_var, values=chart_options, state="readonly", width=26)
        self.cmb_charts.pack(side="left", padx=5)
        self.cmb_charts.bind("<<ComboboxSelected>>", lambda e: self._render_active_chart())

        self.chart_container = ttk.Frame(self.tab_charts)
        self.chart_container.pack(fill="both", expand=True)

        self.canvas_widget: Optional[FigureCanvasTkAgg] = None

    def _render_active_chart(self) -> None:
        if not self.statistics_report:
            return

        # Clear existing canvas
        for child in self.chart_container.winfo_children():
            child.destroy()

        chart_choice = self.chart_var.get()
        if chart_choice == "Protocol Distribution":
            fig = plot_protocol_distribution(self.statistics_report)
        elif chart_choice == "Traffic Volume Over Time":
            fig = plot_traffic_over_time(self.statistics_report)
        elif chart_choice == "Top Endpoints":
            fig = plot_top_endpoints(self.statistics_report)
        elif chart_choice == "Packet Length Bins":
            fig = plot_packet_size_distribution(self.statistics_report)
        else:
            fig = plot_alerts_summary(self.alerts)

        self.canvas_widget = FigureCanvasTkAgg(fig, master=self.chart_container)
        self.canvas_widget.draw()
        self.canvas_widget.get_tk_widget().pack(fill="both", expand=True)

    # ---------------- TAB 6: EXPORT ----------------
    def _build_tab_export(self) -> None:
        group = ttk.LabelFrame(self.tab_export, text=" Generate & Save Reports ", padding=15)
        group.pack(fill="both", expand=True)

        ttk.Label(group, text="Destination Directory:").grid(row=0, column=0, sticky="w", pady=5)
        self.ent_export_dir = ttk.Entry(group, width=50)
        self.ent_export_dir.grid(row=0, column=1, sticky="ew", padx=6, pady=5)
        self.ent_export_dir.insert(0, str(Path("reports").resolve()))

        btn_browse_dir = ttk.Button(group, text="Browse Dir...", command=self._on_browse_export_dir)
        btn_browse_dir.grid(row=0, column=2, padx=4, pady=5)

        group.columnconfigure(1, weight=1)

        btn_frame = ttk.Frame(group, padding=(0, 15))
        btn_frame.grid(row=1, column=0, columnspan=3, sticky="w")

        ttk.Button(btn_frame, text="Export All Formats (CSV + JSON + MD)", style="Primary.TButton", command=self._export_all).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Export CSVs Only", command=self._export_csvs).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Export JSON Only", command=self._export_json).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Export Markdown Report", command=self._export_markdown).pack(side="left", padx=5)

        self.lbl_export_status = ttk.Label(group, text="", font=("Segoe UI", 9, "italic"))
        self.lbl_export_status.grid(row=2, column=0, columnspan=3, sticky="w", pady=10)

    def _on_browse_export_dir(self) -> None:
        d = filedialog.askdirectory(initialdir=self.ent_export_dir.get())
        if d:
            self.ent_export_dir.delete(0, "end")
            self.ent_export_dir.insert(0, d)

    def _export_all(self) -> None:
        self._export_csvs()
        self._export_json()
        self._export_markdown()
        self.lbl_export_status.config(text=f"[+] Successfully exported all formats to {self.ent_export_dir.get()}", foreground="green")

    def _export_csvs(self) -> None:
        if not self.analysis_summary or not self.statistics_report:
            messagebox.showwarning("Export Warning", "No completed analysis to export.")
            return
        out_dir = Path(self.ent_export_dir.get())
        export_flows_csv(self.flows, out_dir / "flows.csv")
        export_alerts_csv(self.alerts, out_dir / "alerts.csv")
        export_endpoints_csv(self.statistics_report.endpoints, out_dir / "endpoints.csv")
        self.lbl_export_status.config(text=f"[+] CSVs exported to {out_dir}", foreground="green")

    def _export_json(self) -> None:
        if not self.analysis_summary or not self.statistics_report:
            messagebox.showwarning("Export Warning", "No completed analysis to export.")
            return
        out_dir = Path(self.ent_export_dir.get())
        export_json(self.analysis_summary, self.statistics_report, self.flows, self.alerts, self.config, out_dir / "report.json")
        self.lbl_export_status.config(text=f"[+] JSON report exported to {out_dir / 'report.json'}", foreground="green")

    def _export_markdown(self) -> None:
        if not self.analysis_summary or not self.statistics_report:
            messagebox.showwarning("Export Warning", "No completed analysis to export.")
            return
        out_dir = Path(self.ent_export_dir.get())
        export_markdown_report(self.analysis_summary, self.statistics_report, self.flows, self.alerts, self.config, out_dir / "report.md")
        self.lbl_export_status.config(text=f"[+] Markdown report exported to {out_dir / 'report.md'}", foreground="green")

    # ---------------- HELPERS & WORKER THREAD ----------------
    def _on_browse(self) -> None:
        fp = filedialog.askopenfilename(
            title="Select Packet Capture",
            filetypes=[
                ("Capture Files", "*.pcap;*.pcapng;*.cap"),
                ("PCAP Files", "*.pcap"),
                ("PCAPNG Files", "*.pcapng"),
                ("All Files", "*.*"),
            ],
        )
        if fp:
            self.ent_filepath.delete(0, "end")
            self.ent_filepath.insert(0, fp)
            self.current_capture_path = Path(fp)

    def _on_analyze(self) -> None:
        fp_str = self.ent_filepath.get().strip()
        if not fp_str:
            messagebox.showwarning("Input Missing", "Please select a PCAP or PCAPNG file first.")
            return
        p = Path(fp_str)
        if not p.is_file():
            messagebox.showerror("File Error", f"Capture file not found:\n{fp_str}")
            return

        self.current_capture_path = p
        self.is_analyzing = True
        self.btn_analyze.config(state="disabled")
        self.progress_bar.start(10)
        self.lbl_status.config(text=f"Analysing capture: {p.name} ...")
        self.lbl_runtime.config(text="")

        # Launch background worker
        worker = threading.Thread(target=self._worker_analysis, args=(p,), daemon=True)
        worker.start()

    def _worker_analysis(self, capture_file: Path) -> None:
        try:
            summary, stats, flows, alerts = run_analysis_pipeline(
                capture_path=capture_file,
                config=self.config,
            )
            self.msg_queue.put(("SUCCESS", (summary, stats, flows, alerts)))
        except Exception as e:
            self.msg_queue.put(("ERROR", str(e)))

    def _poll_queue(self) -> None:
        try:
            while True:
                msg_type, data = self.msg_queue.get_nowait()
                if msg_type == "SUCCESS":
                    summary, stats, flows, alerts = data
                    self._on_analysis_complete(summary, stats, flows, alerts)
                elif msg_type == "ERROR":
                    self._on_analysis_failed(data)
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_queue)

    def _on_analysis_complete(
        self,
        summary: AnalysisSummary,
        stats: StatisticsReport,
        flows: List[FlowRecord],
        alerts: List[AlertRecord],
    ) -> None:
        self.is_analyzing = False
        self.progress_bar.stop()
        self.btn_analyze.config(state="normal")

        self.analysis_summary = summary
        self.statistics_report = stats
        self.flows = flows
        self.alerts = alerts

        # Update status
        self.lbl_status.config(text=f"Analysis complete: {summary.packets_processed:,} packets processed.")
        self.lbl_runtime.config(text=f"Runtime: {summary.analysis_duration_seconds:.2f}s")

        # Update metric cards
        self.metric_cards["Packets Processed"].config(text=f"{summary.packets_processed:,}")
        self.metric_cards["Observed Bytes"].config(text=f"{summary.total_bytes / 1024:.1f} KB")
        self.metric_cards["Distinct Endpoints"].config(text=f"{summary.distinct_endpoints:,}")
        self.metric_cards["Identified Flows"].config(text=f"{summary.identified_flows:,}")
        self.metric_cards["Distinct Protocols"].config(text=f"{len(summary.protocols_observed)}")
        self.metric_cards["Anomaly Alerts"].config(
            text=f"{summary.alerts_generated}",
            fg=self.c_accent if summary.alerts_generated > 0 else self.c_primary,
        )

        # Update Overview text
        meta_str = (
            f"File Path        : {summary.capture_file}\n"
            f"File Size        : {summary.file_size_bytes:,} bytes\n"
            f"Packets Ok       : {summary.packets_processed:,}\n"
            f"Packets Errored  : {summary.packets_skipped + summary.packets_partial:,}\n"
            f"Capture Duration : {summary.capture_duration_seconds:.2f} seconds\n"
            f"Avg Packet Size  : {stats.packet_sizes.mean_length:.1f} bytes\n"
            f"Max Packet Size  : {stats.packet_sizes.max_length} bytes\n"
            f"Top 1 Talker     : {stats.traffic_concentration_top1_pct:.1f}% concentration\n"
            f"Top 3 Talkers    : {stats.traffic_concentration_top3_pct:.1f}% concentration\n"
        )
        self.txt_metadata.config(state="normal")
        self.txt_metadata.delete("1.0", "end")
        self.txt_metadata.insert("1.0", meta_str)
        self.txt_metadata.config(state="disabled")

        # Update Protocols Table
        for item in self.tree_proto.get_children():
            self.tree_proto.delete(item)
        for p, m in sorted(stats.protocols.items(), key=lambda x: x[1].packet_count, reverse=True):
            self.tree_proto.insert("", "end", values=(p, f"{m.packet_count:,}", f"{m.packet_percentage:.1f}%", f"{m.byte_count:,}", f"{m.byte_percentage:.1f}%"))

        # Update Flows Table
        for item in self.tree_flows.get_children():
            self.tree_flows.delete(item)
        for f in flows[:2000]:  # Bound GUI rows to 2000 for smooth responsiveness
            self.tree_flows.insert("", "end", values=(
                f.protocol,
                f.endpoint_a_str,
                f.endpoint_b_str,
                f"{f.packets_a_to_b:,}",
                f"{f.packets_b_to_a:,}",
                f"{f.total_packets:,}",
                f"{f.total_bytes:,}",
                f"{f.duration:.2f}",
            ))

        # Update Endpoints Table
        for item in self.tree_endpoints.get_children():
            self.tree_endpoints.delete(item)
        for ep in sorted(stats.endpoints.values(), key=lambda e: e.total_packets, reverse=True)[:1000]:
            self.tree_endpoints.insert("", "end", values=(
                ep.endpoint,
                f"{ep.packets_sent:,}",
                f"{ep.packets_received:,}",
                f"{ep.total_packets:,}",
                f"{ep.total_bytes:,}",
                ep.distinct_dest_ports,
            ))

        # Update Alerts Table
        for item in self.tree_alerts.get_children():
            self.tree_alerts.delete(item)
        for a in alerts:
            item_id = self.tree_alerts.insert("", "end", values=(
                a.severity,
                a.alert_id,
                a.rule_name,
                a.endpoint,
                a.observed_value,
                a.threshold,
            ))
            # Tag severity color
            tag_name = a.severity
            self.tree_alerts.tag_configure(tag_name, background=self.tag_colors.get(tag_name, "#ffffff"))
            self.tree_alerts.item(item_id, tags=(tag_name,))

        # Render Active Chart
        self._render_active_chart()

    def _on_analysis_failed(self, error_message: str) -> None:
        self.is_analyzing = False
        self.progress_bar.stop()
        self.btn_analyze.config(state="normal")
        self.lbl_status.config(text=f"Analysis failed: {error_message}")
        messagebox.showerror("Analysis Error", f"An error occurred during capture analysis:\n\n{error_message}")

    def _sort_treeview(self, tree: ttk.Treeview, col: str, reverse: bool) -> None:
        """Sort Treeview column numerically if possible, otherwise alphabetically."""
        l = [(tree.set(k, col), k) for k in tree.get_children("")]

        # Helper to convert strings to numbers for sorting
        def parse_sort_val(v: str) -> Any:
            cleaned = v.replace(",", "").replace("%", "").strip()
            try:
                return float(cleaned)
            except ValueError:
                return v.lower()

        l.sort(key=lambda t: parse_sort_val(t[0]), reverse=reverse)

        for index, (_, k) in enumerate(l):
            tree.move(k, "", index)

        # Toggle sort direction on next header click
        tree.heading(col, command=lambda: self._sort_treeview(tree, col, not reverse))


def launch_gui() -> None:
    """Launch NetScope desktop GUI application."""
    app = NetScopeGUI()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
