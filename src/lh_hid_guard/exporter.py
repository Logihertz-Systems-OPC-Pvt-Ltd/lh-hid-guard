# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        src.lh_hid_guard.exporter
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Exporters for security audit findings in Rich Table, JSON, and SARIF v2.1.0 formats.

This module formats timing analysis and USB hardware audit results for interactive
terminal review, SIEM automated pipelines (JSON), and GitHub / GitLab security
scanning integration (OASIS SARIF v2.1.0).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_hid_guard.models import TimingAnalysisSummary, UsbScanResult

SARIF_SCHEMA_V210 = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "lh-hid-guard"
TOOL_VERSION = "0.1.0"
TOOL_INFO_URI = "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-hid-guard"

RULES = {
    "LH-HID-001": {
        "name": "SuperhumanKeystrokeInjection",
        "shortDescription": {"text": "Automated keystroke injection timing anomaly detected."},
        "fullDescription": {
            "text": (
                "The rolling inter-keystroke interval (IKI) dropped below the physical human "
                "actuation threshold (< 8.0ms), indicating automated hardware injection "
                "(e.g. BadUSB)."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "LH-HID-002": {
        "name": "UnauthorizedUsbDevice",
        "shortDescription": {"text": "Unapproved USB device detected on Linux endpoint."},
        "fullDescription": {
            "text": (
                "A connected USB device was not found in the organization's approved "
                "device allowlist."
            )
        },
        "defaultConfiguration": {"level": "error"},
    },
    "LH-HID-003": {
        "name": "CompositeStorageKeyboardAnomaly",
        "shortDescription": {"text": "Suspicious composite Storage + Keyboard USB device."},
        "fullDescription": {
            "text": (
                "A USB peripheral advertises both Mass Storage (08) and Keyboard (03) interfaces, "
                "characteristic of hardware attack platforms (e.g. USB Rubber Ducky, MalDuino)."
            )
        },
        "defaultConfiguration": {"level": "warning"},
    },
}


def build_timing_summary_table(summary: TimingAnalysisSummary) -> Table:
    """Build a Rich table displaying the overall keystroke timing metrics."""
    table = Table(
        title="⌨️  Logihertz Keystroke Timing & IKI Metrics",
        box=ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Metric", style="bold white", width=28)
    table.add_column("Value", style="yellow")
    table.add_column("Reference Limit / Status", style="green")

    status_text = (
        "[bold red]THREAT DETECTED[/bold red]"
        if summary.has_threats
        else "[bold green]CLEAN (HUMAN)[/bold green]"
    )

    table.add_row("Total Keystroke Events", str(summary.total_events), "-")
    table.add_row("Calculated Intervals (IKI)", str(summary.total_intervals), "-")
    table.add_row(
        "Overall Mean IKI",
        f"{summary.overall_mean_iki_ms:.2f} ms",
        f"> {summary.threshold_ms:.1f} ms threshold",
    )
    table.add_row(
        "Overall Std Dev (Jitter)",
        f"{summary.overall_std_dev_iki_ms:.2f} ms",
        "Human variance typically > 25 ms",
    )
    table.add_row(
        "Min / Max IKI", f"{summary.min_iki_ms:.2f} ms / {summary.max_iki_ms:.2f} ms", "-"
    )
    table.add_row(
        "Burst Typing Speed",
        f"{summary.overall_kps:.1f} keys/s ({summary.overall_wpm:.1f} WPM)",
        "-",
    )
    table.add_row(
        "Injection Window Threshold",
        f"{summary.threshold_ms:.1f} ms (window={summary.window_size})",
        "-",
    )
    table.add_row("Anomalous Windows Found", str(summary.anomaly_count), status_text)

    return table


def build_timing_anomalies_table(summary: TimingAnalysisSummary) -> Table:
    """Build a Rich table listing specific anomalous injection windows."""
    table = Table(
        title="🚨 Detected Keystroke Injection Burst Windows",
        box=ROUNDED,
        header_style="bold red",
    )
    table.add_column("Window", style="bold cyan", width=8)
    table.add_column("Intervals", style="white", width=12)
    table.add_column("Mean IKI", style="bold red", width=12)
    table.add_column("Std Dev", style="yellow", width=10)
    table.add_column("Burst Speed", style="magenta", width=16)
    table.add_column("Reason / Attack Signature", style="bold yellow")

    for anomaly in summary.anomalies:
        table.add_row(
            f"#{anomaly.window_index}",
            f"{anomaly.start_interval_idx}-{anomaly.end_interval_idx}",
            f"{anomaly.mean_iki_ms:.2f} ms",
            f"{anomaly.std_dev_iki_ms:.2f} ms",
            f"{anomaly.burst_speed_kps:.1f} kps",
            anomaly.reason,
        )

    return table


def render_timing_table(summary: TimingAnalysisSummary, console: Console | None = None) -> str:
    """Render the keystroke timing audit to terminal or return captured formatted string."""
    c = console or Console()
    with c.capture() as capture:
        c.print(build_timing_summary_table(summary))
        if summary.has_threats:
            c.print()
            c.print(build_timing_anomalies_table(summary))
            panel_text = Text.from_markup(
                f"[bold red]ALERT:[/bold red] Detected [bold white]{summary.anomaly_count}"
                f"[/bold white] superhuman injection bursts (mean IKI < "
                f"{summary.threshold_ms:.1f} ms). "
                "High probability of automated BadUSB / keystroke injection hardware."
            )
            c.print(Panel(panel_text, border_style="red", title="SECURITY INCIDENT ALERT"))
        else:
            panel_text = Text.from_markup(
                "[bold green]OK:[/bold green] All typing timing intervals conform to natural "
                "human neuromuscular actuation constraints."
            )
            c.print(Panel(panel_text, border_style="green", title="STATUS SECURE"))
    return capture.get()


def export_timing_json(summary: TimingAnalysisSummary) -> str:
    """Export keystroke timing analysis summary as a formatted JSON string."""
    payload: dict[str, Any] = {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "info": TOOL_INFO_URI},
        "type": "keystroke_timing_analysis",
        "has_threats": summary.has_threats,
        "summary": summary.to_dict(),
    }
    return json.dumps(payload, indent=2)


def export_timing_sarif(
    summary: TimingAnalysisSummary,
    source_uri: str = "events.json",
) -> str:
    """Export keystroke timing analysis results into OASIS SARIF v2.1.0 format."""
    results: list[dict[str, Any]] = []

    for anomaly in summary.anomalies:
        rule_id = "LH-HID-001"
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": 0,
                "level": "error",
                "message": {
                    "text": (
                        f"Superhuman keystroke injection burst in window #{anomaly.window_index} "
                        f"(intervals {anomaly.start_interval_idx} to {anomaly.end_interval_idx}): "
                        f"average IKI {anomaly.mean_iki_ms:.2f}ms "
                        f"(< {summary.threshold_ms:.1f}ms limit), "
                        f"burst speed {anomaly.burst_speed_kps:.1f} keys/s "
                        f"({anomaly.burst_speed_wpm:.1f} WPM)."
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": source_uri},
                            "region": {
                                "startLine": max(1, anomaly.start_interval_idx + 1),
                                "endLine": max(1, anomaly.end_interval_idx + 1),
                            },
                        }
                    }
                ],
                "properties": {
                    "window_index": anomaly.window_index,
                    "mean_iki_ms": anomaly.mean_iki_ms,
                    "std_dev_iki_ms": anomaly.std_dev_iki_ms,
                    "burst_speed_kps": anomaly.burst_speed_kps,
                    "burst_speed_wpm": anomaly.burst_speed_wpm,
                },
            }
        )

    rules_list = [
        {
            "id": k,
            "name": v["name"],
            "shortDescription": v["shortDescription"],
            "fullDescription": v["fullDescription"],
            "defaultConfiguration": v["defaultConfiguration"],
        }
        for k, v in RULES.items()
        if k == "LH-HID-001"
    ]

    sarif_doc = {
        "$schema": SARIF_SCHEMA_V210,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "rules": rules_list,
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)


def build_usb_device_table(result: UsbScanResult) -> Table:
    """Build a Rich table displaying discovered USB devices and security status."""
    table = Table(
        title="🔌 Logihertz Linux Sysfs USB Device Audit",
        box=ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Bus ID", style="bold white", width=10)
    table.add_column("VID:PID", style="bold yellow", width=11)
    table.add_column("Manufacturer / Product", style="white")
    table.add_column("Interfaces (Class/Sub/Proto)", style="cyan")
    table.add_column("Allowlist", style="bold", width=12)
    table.add_column("Security Findings", style="bold red")

    for dev in result.devices:
        if dev.is_hub:
            continue

        iface_strings = [
            f"{iface.interface_name}[{iface.class_code}:{iface.subclass_code}:{iface.protocol_code}]"
            for iface in dev.interfaces
        ]
        iface_summary = "\n".join(iface_strings) if iface_strings else "None"

        allow_style = "[green]AUTHORIZED[/green]" if dev.is_allowed else "[red]UNAUTHORIZED[/red]"
        findings = "\n".join(dev.anomalies) if dev.anomalies else "[green]None (Clean)[/green]"

        product_label = f"{dev.manufacturer} {dev.product}".strip() or "Unknown USB Device"

        table.add_row(
            dev.bus_id,
            dev.vid_pid,
            product_label,
            iface_summary,
            allow_style,
            findings,
        )

    return table


def render_usb_table(result: UsbScanResult, console: Console | None = None) -> str:
    """Render the USB scan inventory table and security verdict."""
    c = console or Console()
    with c.capture() as capture:
        c.print(build_usb_device_table(result))
        c.print()
        if result.has_threats:
            summary_msg = (
                f"[bold red]SECURITY THREATS DETECTED:[/bold red] "
                f"[bold white]{result.unauthorized_count}[/bold white] unauthorized device(s), "
                f"[bold white]{result.anomaly_count}[/bold white] hardware anomalies."
            )
            c.print(Panel(Text.from_markup(summary_msg), border_style="red", title="AUDIT ALERT"))
        else:
            summary_msg = (
                f"[bold green]SYSFS SCAN CLEAN:[/bold green] All "
                f"[bold white]{result.total_scanned}[/bold white] "
                "scanned devices are authorized with zero composite hardware anomalies."
            )
            c.print(Panel(Text.from_markup(summary_msg), border_style="green", title="AUDIT PASS"))
    return capture.get()


def export_usb_json(result: UsbScanResult) -> str:
    """Export USB audit scan result as a formatted JSON string."""
    payload: dict[str, Any] = {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "info": TOOL_INFO_URI},
        "type": "usb_sysfs_scan",
        "has_threats": result.has_threats,
        "summary": result.to_dict(),
    }
    return json.dumps(payload, indent=2)


def export_usb_sarif(result: UsbScanResult) -> str:
    """Export USB scan findings into OASIS SARIF v2.1.0 format."""
    results: list[dict[str, Any]] = []

    for dev in result.devices:
        if dev.is_hub:
            continue

        if not dev.is_allowed:
            results.append(
                {
                    "ruleId": "LH-HID-002",
                    "level": "error",
                    "message": {
                        "text": (
                            f"Unauthorized USB device detected: VID:PID '{dev.vid_pid}' "
                            f"({dev.manufacturer} {dev.product}) at bus '{dev.bus_id}'."
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": dev.sysfs_path or f"/sys/bus/usb/devices/{dev.bus_id}"
                                }
                            }
                        }
                    ],
                }
            )

        if dev.has_composite_anomaly:
            results.append(
                {
                    "ruleId": "LH-HID-003",
                    "level": "warning",
                    "message": {
                        "text": (
                            f"Composite Storage + Keyboard anomaly: device '{dev.vid_pid}' "
                            f"at '{dev.bus_id}' exposes both Mass Storage (08) and "
                            "Keyboard (03) interfaces."
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": dev.sysfs_path or f"/sys/bus/usb/devices/{dev.bus_id}"
                                }
                            }
                        }
                    ],
                }
            )

    sarif_doc = {
        "$schema": SARIF_SCHEMA_V210,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "rules": [
                            {"id": k, **v}
                            for k, v in RULES.items()
                            if k in ("LH-HID-002", "LH-HID-003")
                        ],
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)


def write_output(content: str, output_path: str | Path | None) -> None:
    """Write rendered report content to file or print to stdout.

    Args:
        content: Formatted report text.
        output_path: Destination file path, or None for stdout.
    """
    if output_path:
        dest = Path(output_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
    else:
        print(content)
