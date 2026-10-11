"""Unit coverage for incremental analysis without privileged capture."""
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
import threading

from netscope.live import LiveAnalyzer, LiveCaptureSession, capture_backend_status
from netscope.parser import stream_packets


def test_live_analyzer_aggregates_both_directions_and_bounds_history():
    analyzer = LiveAnalyzer(history_limit=2, flow_limit=10)
    analyzer.process(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1200, dport=443))
    result = analyzer.process(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=443, dport=1200))
    analyzer.process(Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=1201, dport=80))

    assert result["packets"] == 2
    assert result["flows"] == 1
    assert analyzer.packet_count == 3
    assert len(analyzer.packets) == 2
    assert analyzer.flows.flow_count == 2
    bidirectional = next(flow for flow in analyzer.flows.get_flows() if flow.total_packets == 2)
    assert bidirectional.total_packets == 2
    assert bidirectional.packets_a_to_b == bidirectional.packets_b_to_a == 1


def test_capture_session_start_stop_with_mocked_backend(monkeypatch, tmp_path):
    from scapy import all as scapy_all

    class FakeSniffer:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.running = False
            self.stopped = threading.Event()

        def start(self):
            self.running = True

        def stop(self, join=True):
            self.running = False
            self.stopped.set()

        def join(self):
            self.stopped.wait(timeout=2)

    monkeypatch.setattr(scapy_all, "AsyncSniffer", FakeSniffer)
    seen = []
    output = tmp_path / "session.pcapng"
    session = LiveCaptureSession("test0", seen.append, capture_filter="tcp", output_path=output)
    session.start()
    assert session.state == "Capturing"
    assert session.sniffer.kwargs["store"] is False
    assert session.sniffer.kwargs["filter"] == "tcp"
    session.sniffer.kwargs["prn"](Ether() / IP(src="198.51.100.1", dst="198.51.100.2") / TCP())
    session.stop()
    assert session.state == "Stopped"
    assert session.writer is None
    assert output.stat().st_size > 0
    assert len(list(stream_packets(output))) == 1
    session.stop()
    assert session.state == "Stopped"


def test_capture_start_failure_is_actionable(monkeypatch):
    from scapy import all as scapy_all

    class BrokenSniffer:
        def __init__(self, **kwargs):
            pass

        def start(self):
            raise OSError("permission denied")

    monkeypatch.setattr(scapy_all, "AsyncSniffer", BrokenSniffer)
    session = LiveCaptureSession("test0", lambda packet: None)
    try:
        session.start()
    except RuntimeError as exc:
        assert "permission" in str(exc)
    else:
        raise AssertionError("start failure should be reported")
    assert session.state == "Error"


def test_flow_aggregator_expires_inactive_flows():
    from netscope.flows import FlowAggregator
    from netscope.models import PacketRecord

    flows = FlowAggregator()
    flows.add_packet(PacketRecord.create(1, 10.0, "192.0.2.1", "192.0.2.2", "UDP", 10, 20, 32))
    assert flows.expire_before(10.0) == 0
    assert flows.expire_before(10.1) == 1
    assert flows.flow_count == 0


def test_backend_check_reports_missing_npcap(monkeypatch):
    from scapy.all import conf
    import netscope.live as live

    monkeypatch.setattr(live.sys, "platform", "win32")
    monkeypatch.setattr(conf, "use_pcap", False)
    available, message = capture_backend_status()

    assert not available
    assert "Npcap" in message
