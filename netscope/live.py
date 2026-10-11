"""Live packet capture and bounded incremental analysis helpers.

Capture uses Scapy's libpcap/Npcap-backed AsyncSniffer. Raw packets are never
retained unless the caller enables PCAPNG recording.
"""
from __future__ import annotations

import queue
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Optional

from netscope.config import DetectionConfig
from netscope.detectors import DetectionEngine
from netscope.flows import FlowAggregator
from netscope.models import PacketRecord
from netscope.parser import _dissect_scapy_packet
from netscope.statistics import calculate_statistics


def discover_interfaces() -> list[tuple[str, str]]:
    """Return (identifier, display name) pairs or raise an actionable error."""
    try:
        from scapy.all import get_if_list, conf
        display_by_capture_id = {}
        if sys.platform.startswith("win"):
            try:
                from scapy.arch.windows import get_windows_if_list
                for item in get_windows_if_list():
                    capture_id = rf"\Device\NPF_{item.get('guid', '')}"
                    friendly = item.get("name") or item.get("description") or capture_id
                    description = item.get("description")
                    display_by_capture_id[capture_id] = f"{friendly} — {description}" if description and description != friendly else friendly
            except Exception:
                pass
        result = []
        for name in get_if_list():
            label = display_by_capture_id.get(name)
            if not label:
                try:
                    dev = conf.ifaces.dev_from_name(name)
                    label = getattr(dev, "description", None) or getattr(dev, "name", None) or name
                except Exception:
                    label = name
            result.append((name, str(label)))
        return result
    except Exception as exc:
        raise RuntimeError(f"Could not enumerate capture interfaces: {exc}. Check that Npcap (Windows) or libpcap (Linux/macOS) is installed.") from exc


class LiveAnalyzer:
    """Incremental shared-flow processing with bounded packet/alert history."""

    def __init__(self, config: Optional[DetectionConfig] = None, history_limit: int = 5000,
                 flow_limit: int = 10000, flow_timeout_sec: float = 300.0) -> None:
        if history_limit < 1 or flow_limit < 1 or flow_timeout_sec <= 0:
            raise ValueError("History/flow limits and flow timeout must be positive")
        self.config = config or DetectionConfig()
        self.config.validate()
        self.history_limit = history_limit
        self.flow_limit = flow_limit
        self.flow_timeout_sec = flow_timeout_sec
        self.packets: deque[PacketRecord] = deque(maxlen=history_limit)
        self.flows = FlowAggregator()
        self.packet_count = 0
        self.byte_count = 0
        self.dropped_events = 0
        self._index = 0
        self._lock = threading.Lock()
        self._alerts = {}
        self._last_evaluation = 0.0
        self._last_flow_maintenance = 0.0

    def process(self, packet: object) -> dict:
        with self._lock:
            self._index += 1
            record = _dissect_scapy_packet(packet, self._index)
            if not (record.timestamp > 0):
                record.timestamp = time.time()
            self.packet_count += 1
            self.byte_count += record.wire_length or record.length
            self.packets.append(record)
            self.flows.add_packet(record)
            now = time.monotonic()
            if now - self._last_flow_maintenance >= 1.0:
                self.flows.expire_before(record.timestamp - self.flow_timeout_sec)
                self.flows.retain_most_recent(self.flow_limit)
                self._last_flow_maintenance = now
            alerts = []
            if now - self._last_evaluation >= 1.0:
                recent = list(self.packets)
                flows = self.flows.get_flows()
                stats = calculate_statistics(recent, flows, interval_sec=self.config.time_bucket_interval_sec)
                alerts = DetectionEngine(self.config).run(recent, flows, stats)
                self._last_evaluation = now
            new_alerts = []
            for alert in alerts:
                key = (alert.rule_id, alert.endpoint)
                if key not in self._alerts:
                    self._alerts[key] = alert
                    new_alerts.append(alert)
            # Bounded deduplication memory.
            if len(self._alerts) > 500:
                self._alerts = dict(list(self._alerts.items())[-250:])
            return {"packets": self.packet_count, "bytes": self.byte_count,
                    "flows": self.flows.flow_count, "alerts": len(self._alerts),
                    "new_alerts": new_alerts}


class LiveCaptureSession:
    """One-shot AsyncSniffer session with explicit start/stop lifecycle."""

    def __init__(self, interface: str, on_packet: Callable[[object], None],
                 capture_filter: str = "", output_path: Optional[str | Path] = None) -> None:
        if not interface:
            raise ValueError("Select a network interface before starting capture")
        self.interface = interface
        self.on_packet = on_packet
        self.capture_filter = capture_filter.strip() or None
        self.output_path = Path(output_path) if output_path else None
        self.sniffer = None
        self.writer = None
        self.state = "Idle"
        self.error: Optional[str] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            if self.state not in ("Idle", "Stopped", "Error"):
                raise RuntimeError(f"Capture cannot start while {self.state.lower()}")
            self.state = "Starting"
            self.error = None
            try:
                from scapy.all import AsyncSniffer
                def handle_packet(packet: object) -> None:
                    if self.writer is not None:
                        self.writer.write(packet)
                    self.on_packet(packet)
                kwargs = {"iface": self.interface, "prn": handle_packet, "store": False}
                if self.capture_filter:
                    kwargs["filter"] = self.capture_filter
                if self.output_path:
                    self.output_path.parent.mkdir(parents=True, exist_ok=True)
                    from scapy.utils import PcapNgWriter
                    self.writer = PcapNgWriter(str(self.output_path))
                self.sniffer = AsyncSniffer(**kwargs)
                self.sniffer.start()
                deadline = time.monotonic() + 2.0
                while not getattr(self.sniffer, "running", False):
                    thread = getattr(self.sniffer, "thread", None)
                    if getattr(self.sniffer, "exception", None) is not None:
                        raise self.sniffer.exception
                    if thread is not None and not thread.is_alive():
                        self.sniffer.join()
                        raise RuntimeError("Capture worker exited before opening the interface")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Capture backend did not finish initializing within 2 seconds")
                    time.sleep(0.01)
                # AsyncSniffer.start() only launches a thread. Give its socket
                # setup a brief stability check before exposing Capturing state.
                time.sleep(0.1)
                if getattr(self.sniffer, "exception", None) is not None:
                    raise self.sniffer.exception
                if not getattr(self.sniffer, "running", False):
                    raise RuntimeError("Capture worker exited during interface initialization")
                self.state = "Capturing"
                threading.Thread(target=self._watch_capture, daemon=True).start()
            except Exception as exc:
                self.state = "Error"
                if self.writer is not None:
                    self.writer.close()
                    self.writer = None
                self.sniffer = None
                raise RuntimeError(f"Could not start capture on {self.interface}: {exc}. Check that Npcap (Windows) or libpcap (Linux/macOS) is installed, the interface/filter is valid, and the current user has capture permission.") from exc

    def _watch_capture(self) -> None:
        """Notice unexpected backend termination without touching GUI state."""
        try:
            if self.sniffer is not None:
                self.sniffer.join()
        except Exception as exc:
            with self._lock:
                if self.state == "Capturing":
                    self.state = "Error"
                    self.error = f"Capture worker stopped unexpectedly: {exc}. Check Npcap/libpcap, interface availability, and capture permissions."
            return
        with self._lock:
            if self.state == "Capturing":
                self.state = "Error"
                self.error = "Capture worker stopped unexpectedly."

    def stop(self) -> None:
        with self._lock:
            if self.state in ("Stopped", "Idle") or (self.state == "Error" and not getattr(self.sniffer, "running", False)):
                self.state = "Stopped"
                return
            self.state = "Stopping"
            sniffer = self.sniffer
        try:
            if sniffer is not None and getattr(sniffer, "running", False):
                sniffer.stop(join=True)
            failure = getattr(sniffer, "exception", None) if sniffer is not None else None
            if failure is not None:
                self.error = f"Capture stopped with an error: {failure}. Check Npcap/libpcap, interface availability, and capture permissions."
                raise RuntimeError(self.error)
        except Exception as exc:
            if self.error is None:
                self.error = f"Could not stop capture cleanly: {exc}. Check Npcap/libpcap and capture permissions."
            raise RuntimeError(self.error) from exc
        finally:
            if self.writer is not None:
                self.writer.close()
                self.writer = None
            with self._lock:
                self.state = "Error" if self.error else "Stopped"
