# NetScope Testing

The automated suite uses synthetic Scapy packets, temporary capture files, and mocked capture backends. It does not open physical interfaces or require administrator/root privileges.

Run it from the repository root:

```powershell
python -m pytest -v
```

## Coverage

- `test_parser.py`: PCAP/PCAPNG validation and packet field normalization.
- `test_flows.py`: canonical keys, reverse direction accounting, and flow metrics.
- `test_statistics.py`: protocol, endpoint, packet-size, and time-bucket metrics.
- `test_detectors.py`: all six offline detection rules and threshold cases.
- `test_reporting.py`: CSV, JSON, Markdown, and PDF output, including empty reports, content, pagination, and export errors.
- `test_cli.py`: CLI arguments, errors, and exports.
- `test_integration.py`: offline analysis pipeline integration.
- `test_live.py`: bounded live packet history, bidirectional flow aggregation, inactivity expiration, mocked capture lifecycle, filters, and PCAPNG recording that is reopened through the offline parser.

Live capture on a real network interface is intentionally not part of the unit suite. To check a local setup manually, list interfaces with `python -m netscope.cli interfaces`, select an interface you are authorised to monitor, start a short capture with `python -m netscope.cli live --interface <id> --duration 10 --record <file.pcapng>`, then analyse the resulting file with the offline CLI.

PDF tests inspect generated PDF bytes for report headings, values, page numbering, and correct error wrapping without requiring a PDF reader application. Live capture on a real network interface is not part of the standard suite.
