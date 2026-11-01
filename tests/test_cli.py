# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the lh-guard command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_hid_guard.cli import app
from tests.test_usb_scanner import create_mock_sysfs_device

runner = CliRunner()


def test_cli_help() -> None:
    """Test --help displays CLI options and commands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "lh-guard" in result.stdout
    assert "analyze-log" in result.stdout
    assert "scan-usb" in result.stdout
    assert "simulate" in result.stdout


def test_cli_simulate(tmp_path: Path) -> None:
    """Test simulation command for both human and injection profiles."""
    human_out = tmp_path / "human_events.json"
    res_human = runner.invoke(
        app, ["simulate", "--profile", "human", "--count", "40", "-o", str(human_out)]
    )
    assert res_human.exit_code == 0
    assert human_out.is_file()

    inj_out = tmp_path / "injection_events.json"
    res_inj = runner.invoke(
        app, ["simulate", "--profile", "injection", "--count", "40", "-o", str(inj_out)]
    )
    assert res_inj.exit_code == 0
    assert inj_out.is_file()

    # Test stdout simulation output without -o
    res_stdout = runner.invoke(app, ["simulate", "--profile", "human", "--count", "5"])
    assert res_stdout.exit_code == 0
    parsed = json.loads(res_stdout.stdout)
    assert len(parsed) == 5


def test_cli_analyze_log_formats(tmp_path: Path) -> None:
    """Test analyze-log with table, json, and sarif formats."""
    # Generate an injection file
    inj_file = tmp_path / "injection.json"
    runner.invoke(app, ["simulate", "--profile", "injection", "--count", "50", "-o", str(inj_file)])

    # 1. Table format to stdout
    res_table = runner.invoke(app, ["analyze-log", str(inj_file)])
    assert res_table.exit_code == 0
    assert "Logihertz Keystroke Timing" in res_table.stdout
    assert "THREAT DETECTED" in res_table.stdout

    # 2. JSON format to file
    json_out = tmp_path / "report.json"
    res_json = runner.invoke(
        app, ["analyze-log", str(inj_file), "--format", "json", "-o", str(json_out)]
    )
    assert res_json.exit_code == 0
    assert json_out.is_file()
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["has_threats"] is True

    # 3. SARIF format to file
    sarif_out = tmp_path / "report.sarif"
    res_sarif = runner.invoke(
        app, ["analyze-log", str(inj_file), "--format", "sarif", "-o", str(sarif_out)]
    )
    assert res_sarif.exit_code == 0
    assert sarif_out.is_file()
    sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"

    # 4. Strict mode failure on threat
    res_strict = runner.invoke(app, ["analyze-log", str(inj_file), "--strict"])
    assert res_strict.exit_code == 1


def test_cli_scan_usb(tmp_path: Path) -> None:
    """Test scan-usb with mocked sysfs directory and allowlist."""
    sysfs_dir = tmp_path / "sysfs_usb"
    sysfs_dir.mkdir()

    # Authorized keyboard
    create_mock_sysfs_device(
        root=sysfs_dir,
        bus_id="1-1",
        vendor_id="046d",
        product_id="c52b",
        manufacturer="Logitech",
        product="Keyboard",
        interfaces=[("1-1:1.0", "03", "01", "01")],
    )

    allowlist_file = tmp_path / "allowlist.json"
    allowlist_file.write_text(json.dumps(["046d:c52b"]), encoding="utf-8")

    # Clean scan
    res_clean = runner.invoke(
        app,
        [
            "scan-usb",
            "--sysfs-path",
            str(sysfs_dir),
            "--allowlist",
            str(allowlist_file),
            "--strict",
        ],
    )
    assert res_clean.exit_code == 0
    assert "SYSFS SCAN CLEAN" in res_clean.stdout

    # Add unauthorized device
    create_mock_sysfs_device(
        root=sysfs_dir,
        bus_id="1-2",
        vendor_id="1234",
        product_id="5678",
        manufacturer="Rogue",
        product="Attacker Device",
    )

    # Scan with JSON format and strict flag (should fail with code 1)
    json_out = tmp_path / "usb_scan.json"
    res_threat = runner.invoke(
        app,
        [
            "scan-usb",
            "--sysfs-path",
            str(sysfs_dir),
            "--allowlist",
            str(allowlist_file),
            "--format",
            "json",
            "-o",
            str(json_out),
            "--strict",
        ],
    )
    assert res_threat.exit_code == 1
    assert json_out.is_file()
    usb_data = json.loads(json_out.read_text(encoding="utf-8"))
    assert usb_data["has_threats"] is True


def test_cli_analyze_clean_and_table_output(tmp_path: Path) -> None:
    """Test analyze-log on clean human typing and output to file."""
    hum_file = tmp_path / "human.json"
    runner.invoke(app, ["simulate", "--profile", "human", "--count", "30", "-o", str(hum_file)])

    # Output table to file
    table_out = tmp_path / "table_report.txt"
    res_table = runner.invoke(
        app,
        ["analyze-log", str(hum_file), "--format", "table", "-o", str(table_out)],
    )
    assert res_table.exit_code == 0
    assert table_out.is_file()

    # Output table to stdout
    res_stdout = runner.invoke(app, ["analyze-log", str(hum_file)])
    assert res_stdout.exit_code == 0
    assert "STATUS OK" in res_stdout.stdout


def test_cli_scan_usb_table_and_sarif(tmp_path: Path) -> None:
    """Test scan-usb table output to file and SARIF format."""
    sysfs_dir = tmp_path / "sysfs_usb2"
    sysfs_dir.mkdir()

    create_mock_sysfs_device(
        root=sysfs_dir,
        bus_id="1-1",
        vendor_id="046d",
        product_id="c52b",
        manufacturer="Logitech",
        product="Keyboard",
        interfaces=[("1-1:1.0", "03", "01", "01")],
    )

    # Table output to file
    table_file = tmp_path / "usb_table.txt"
    res_table = runner.invoke(
        app,
        ["scan-usb", "--sysfs-path", str(sysfs_dir), "-o", str(table_file)],
    )
    assert res_table.exit_code == 0
    assert table_file.is_file()

    # SARIF output
    sarif_file = tmp_path / "usb_sarif.sarif"
    res_sarif = runner.invoke(
        app,
        ["scan-usb", "--sysfs-path", str(sysfs_dir), "--format", "sarif", "-o", str(sarif_file)],
    )
    assert res_sarif.exit_code == 0
    assert sarif_file.is_file()


def test_cli_error_handling(tmp_path: Path) -> None:
    """Test CLI error handling on invalid files or bad inputs."""
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("not json content", encoding="utf-8")

    res = runner.invoke(app, ["analyze-log", str(bad_json)])
    assert res.exit_code == 2

    # Simulate with invalid profile
    res_sim = runner.invoke(app, ["simulate", "--profile", "unknown_profile"])
    assert res_sim.exit_code != 0
