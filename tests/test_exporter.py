# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        tests.test_exporter
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Rich Table, JSON, and SARIF v2.1.0 security exporters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from lh_hid_guard.analyzer import analyze_keystrokes
from lh_hid_guard.exporter import (
    export_timing_json,
    export_timing_sarif,
    export_usb_json,
    export_usb_sarif,
    render_timing_table,
    render_usb_table,
    write_output,
)
from lh_hid_guard.models import UsbDevice, UsbInterface, UsbScanResult
from lh_hid_guard.simulator import generate_human_stream, generate_injection_stream


def test_timing_exporters() -> None:
    """Test table, JSON, and SARIF export for timing analysis."""
    # Threat summary (injection)
    inj_events = generate_injection_stream(count=40, seed=1)
    summary_threat = analyze_keystrokes(inj_events, threshold_ms=8.0, window_size=10)

    # 1. Rich Table rendering
    c = Console(record=True, color_system=None)
    table_text = render_timing_table(summary_threat, console=c)
    assert "Logihertz Keystroke Timing" in table_text
    assert "THREAT DETECTED" in table_text

    # 2. JSON export
    json_str = export_timing_json(summary_threat)
    data = json.loads(json_str)
    assert data["type"] == "keystroke_timing_analysis"
    assert data["has_threats"] is True
    assert data["summary"]["anomaly_count"] > 0

    # 3. SARIF v2.1.0 export
    sarif_str = export_timing_sarif(summary_threat, source_uri="sample_inj.json")
    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "lh-hid-guard"
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "LH-HID-001"
    assert len(sarif["runs"][0]["results"]) > 0
    assert sarif["runs"][0]["results"][0]["ruleId"] == "LH-HID-001"
    assert sarif["runs"][0]["results"][0]["level"] == "error"

    # Clean summary (human)
    hum_events = generate_human_stream(count=40, seed=1)
    summary_clean = analyze_keystrokes(hum_events, threshold_ms=8.0, window_size=10)
    sarif_clean = json.loads(export_timing_sarif(summary_clean))
    assert len(sarif_clean["runs"][0]["results"]) == 0


def test_usb_exporters() -> None:
    """Test table, JSON, and SARIF export for USB hardware audit."""
    dev = UsbDevice(
        bus_id="1-2",
        sysfs_path="/sys/bus/usb/devices/1-2",
        vendor_id="16c0",
        product_id="05df",
        manufacturer="Hak5",
        product="Rubber Ducky",
        interfaces=[
            UsbInterface(
                interface_name="1-2:1.0", class_code="03", subclass_code="01", protocol_code="01"
            ),
            UsbInterface(
                interface_name="1-2:1.1", class_code="08", subclass_code="06", protocol_code="50"
            ),
        ],
        is_allowed=False,
        has_composite_anomaly=True,
        anomalies=["Composite Storage + Keyboard", "Unauthorized VID:PID"],
    )

    scan_res = UsbScanResult(
        sysfs_path="/sys/bus/usb/devices",
        allowlist_path="allowlist.json",
        total_scanned=1,
        authorized_count=0,
        unauthorized_count=1,
        anomaly_count=2,
        devices=[dev],
    )

    # 1. Rich Table rendering
    c = Console(record=True, color_system=None)
    table_text = render_usb_table(scan_res, console=c)
    assert "Logihertz Linux Sysfs USB Device Audit" in table_text
    assert "SECURITY THREATS DETECTED" in table_text

    # 2. JSON export
    json_str = export_usb_json(scan_res)
    data = json.loads(json_str)
    assert data["type"] == "usb_sysfs_scan"
    assert data["has_threats"] is True
    assert data["summary"]["unauthorized_count"] == 1

    # 3. SARIF v2.1.0 export
    sarif_str = export_usb_sarif(scan_res)
    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 2
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "LH-HID-002" in rule_ids
    assert "LH-HID-003" in rule_ids


def test_write_output_file(tmp_path: Path) -> None:
    """Test write_output writing to disk."""
    out_file = tmp_path / "report.txt"
    write_output("Sample Report Text", out_file)
    assert out_file.read_text(encoding="utf-8") == "Sample Report Text"


def test_clean_panels_and_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    """Test clean panel render branches and write_output to stdout."""
    hum_events = generate_human_stream(count=20, seed=1)
    summary_clean = analyze_keystrokes(hum_events, threshold_ms=8.0, window_size=5)

    c = Console(record=True, color_system=None)
    table_text = render_timing_table(summary_clean, console=c)
    assert "STATUS SECURE" in table_text

    clean_scan = UsbScanResult(
        sysfs_path="/sys/bus/usb/devices",
        total_scanned=2,
        authorized_count=2,
        unauthorized_count=0,
        anomaly_count=0,
        devices=[],
    )
    c2 = Console(record=True, color_system=None)
    usb_text = render_usb_table(clean_scan, console=c2)
    assert "AUDIT PASS" in usb_text

    # Write output to stdout (output_path is None)
    write_output("Direct stdout message", None)
    captured = capsys.readouterr()
    assert "Direct stdout message" in captured.out
