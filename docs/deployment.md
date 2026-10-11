# Setup and deployment

## Run from source

NetScope requires Python 3.10+ and Tkinter for its desktop window. From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m netscope.gui
```

On macOS/Linux, activate the environment with `source .venv/bin/activate`. Offline analysis does not require special privileges. The CLI entry point is `python -m netscope.cli`; use `--help` for options.

## Live capture prerequisites

Live capture is performed using Scapy `AsyncSniffer` against a selected interface. It depends on the operating system's packet-capture backend and access permissions:

- **Windows:** Npcap. NetScope can open the [official Npcap download page](https://npcap.com/), but does not silently install a driver. Install it through the official installer and restart NetScope.
- **Linux:** libpcap and permission to capture on the selected interface.
- **macOS:** BPF/libpcap support and permission to access the selected BPF device.

Check interfaces using `python -m netscope.cli interfaces`. Start a short capture only on an interface you are authorised to monitor:

```powershell
python -m netscope.cli live --interface "<interface-id>" --duration 10 --record captures/session.pcapng
python -m netscope.cli --input captures/session.pcapng --output reports/session
```

Ordinary automated tests mock the capture backend and do not verify real hardware capture. Driver installation, operating-system policy, and interface selection require manual checks on each target system.

## Reports

The CLI's default `--format all` writes CSV, JSON, Markdown, and PDF reports. To create only the PDF, use `--format pdf`. Add `--charts` to save standalone PNG charts alongside the report. The GUI's **Reports & Exports** tab offers **Export PDF Report** and **Export All Formats**. GUI PDF writing runs in a worker thread so the window remains responsive.

## CI

GitHub Actions runs the test suite on Ubuntu and Windows with Python 3.10 and 3.11. It also generates the synthetic PCAP and executes the CLI demonstration. CI uses mocked live-capture tests; it does not install Npcap/libpcap or capture from a physical interface.
