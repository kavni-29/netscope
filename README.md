# NetScope - Network Traffic Analyzer

I built NetScope as a third-year CSE project to learn how packet captures can be turned into useful traffic summaries. It is a Python app with a desktop interface and a command-line tool. It can analyse saved PCAP/PCAPNG files and, when the required capture driver is available, monitor a live network interface.

NetScope works with packet and flow metadata. It does not decrypt traffic or prove that an alert is an attack.

## What it does

- Summarises protocols, endpoints, packet sizes, and bidirectional flows.
- Flags unusual traffic patterns using six configurable rules.
- Shows results in a Tkinter desktop app or the command line.
- Exports CSV, JSON, Markdown, and PDF reports, with optional chart images.
- Supports live capture through Scapy when the system's capture backend is set up.

The main processing path is:

```text
PCAP file or live interface -> packet records -> flows and statistics -> alerts and reports
```

## Set up

Use Python 3.10 or later. From PowerShell:

```powershell
git clone https://github.com/kavni-29/netscope.git
cd netscope
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

For macOS or Linux, activate the environment with `source .venv/bin/activate`.

## Run it

### Desktop app

```powershell
python -m netscope.gui
```

Choose a capture file with **Browse**, then click **Analyse Capture**. Use the tabs to review the summary, flows, endpoints, alerts, and charts. The Reports tab can save a PDF by itself or export all report formats.

### Command line

The repository includes a small synthetic capture to try:

```powershell
python -m netscope.cli --input samples/synthetic_demo.pcap --output reports/demo
```

That command writes CSV, JSON, Markdown, and PDF reports. To export only a PDF, add `--format pdf`. To also save chart images, add `--charts`.

Generated reports are local output and are ignored by Git. The `--output reports/demo` option keeps them together in that folder. Without `--output`, the folder is named after the capture file, such as `reports/synthetic_demo`. Delete the reports folder whenever you no longer need those results; the commands recreate it.

To generate the synthetic capture again:

```powershell
python samples/generate_sample_pcap.py
```

### Live monitoring

Open the **Live Monitoring** tab, select an interface, and click **Start Capture**. NetScope listens to traffic already visible on that interface; opening a browser or another networked app can give it packets to display. It does not generate traffic itself.

Live capture needs a system capture backend. On Windows, install [Npcap](https://npcap.com/) and restart NetScope. Linux and macOS also need their packet-capture support and permission to access the chosen interface. You can list interfaces from a terminal with:

```powershell
python -m netscope.cli interfaces
```

Only monitor networks you own or have permission to inspect. The automated tests use a mocked capture backend, so real interface capture still needs to be checked on the target computer.

## Tests

```powershell
python -m pytest -v
```

The tests cover packet parsing, flow aggregation, statistics, detection rules, reports, CLI behavior, and the mocked live-capture lifecycle. In this checkout, **43 tests passed**.

## Project files

```text
netscope/       Main application code (GUI, CLI, analysis, capture, reports)
tests/          Automated tests
samples/        Synthetic capture and its generator
docs/           Design and usage notes
```

## A few limitations

NetScope analyses packet metadata, not encrypted application contents. Its rules are simple heuristics, so ordinary activity can trigger alerts. Live capture also depends on the computer's driver and permissions. Screenshots aren't included yet.

This project has given me practice with packet parsing, flow aggregation, statistics, Tkinter, and testing a shared analysis pipeline from both saved captures and live input.

## More documentation

- [Architecture](docs/architecture.md)
- [Data model](docs/data_model.md)
- [Deployment and setup](docs/deployment.md)
- [Detection rules](docs/detection_rules.md)
- [Testing](docs/testing.md)
