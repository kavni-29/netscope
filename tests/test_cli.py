"""Unit tests for NetScope command-line interface."""

from pathlib import Path
from netscope.cli import main


def test_cli_missing_input_argument(capsys):
    """Test CLI returns exit code 1 when --input is not provided."""
    exit_code = main([])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error: --input capture file is required" in captured.err


def test_cli_nonexistent_file(tmp_path: Path, capsys):
    """Test CLI returns exit code 1 when capture file does not exist."""
    fake_path = tmp_path / "nonexistent.pcap"
    exit_code = main(["--input", str(fake_path)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Invalid Capture Error" in captured.err


def test_cli_invalid_config_file(minimal_pcap_file: Path, tmp_path: Path, capsys):
    """Test CLI returns exit code 1 when provided invalid config."""
    bad_cfg = tmp_path / "bad.json"
    bad_cfg.write_text("{invalid json", encoding="utf-8")

    exit_code = main(["--input", str(minimal_pcap_file), "--config", str(bad_cfg)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Configuration Error" in captured.err


def test_cli_successful_execution(minimal_pcap_file: Path, tmp_path: Path, capsys):
    """Test full CLI execution on valid capture with report exports."""
    out_dir = tmp_path / "cli_out"
    exit_code = main([
        "--input", str(minimal_pcap_file),
        "--output", str(out_dir),
        "--format", "all",
        "--charts",
        "--quiet",
    ])
    assert exit_code == 0
    assert (out_dir / "flows.csv").is_file()
    assert (out_dir / "report.json").is_file()
    assert (out_dir / "report.md").is_file()
    assert (out_dir / "report.pdf").is_file()
    assert (out_dir / "charts" / "protocol_distribution.png").is_file()
