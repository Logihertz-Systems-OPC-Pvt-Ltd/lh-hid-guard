# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        src.lh_hid_guard.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command-line interface for lh-hid-guard.

Implements commands:
    - analyze-log: Inspect keystroke timing streams for superhuman injection bursts.
    - scan-usb: Enumerate Linux sysfs USB devices against an approved allowlist.
    - simulate: Generate synthetic human or hardware keystroke-injection event logs.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from lh_hid_guard.analyzer import analyze_keystrokes, load_keystroke_events
from lh_hid_guard.exporter import (
    build_timing_anomalies_table,
    build_timing_summary_table,
    build_usb_device_table,
    export_timing_json,
    export_timing_sarif,
    export_usb_json,
    export_usb_sarif,
    render_timing_table,
    render_usb_table,
    write_output,
)
from lh_hid_guard.scanner import scan_sysfs_usb
from lh_hid_guard.simulator import simulate_events

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-guard",
    help="Logihertz HID Guard: Defensive Linux CLI against automated keystroke-injection hardware.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


class OutputFormat(StrEnum):
    """Allowed output formats for reports."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class UsbOutputFormat(StrEnum):
    """Allowed output formats for USB scan."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class SimulationProfile(StrEnum):
    """Available simulation profiles."""

    HUMAN = "human"
    INJECTION = "injection"


@app.command(name="analyze-log")
def analyze_log(
    events_file: Annotated[
        Path,
        typer.Argument(
            help="Path to the JSON file containing keystroke event stream.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    threshold_ms: Annotated[
        float,
        typer.Option(
            "--threshold-ms",
            help="Superhuman average IKI threshold in milliseconds.",
        ),
    ] = 8.0,
    window_size: Annotated[
        int,
        typer.Option(
            "--window-size",
            help="Rolling evaluation window size in keystroke intervals.",
        ),
    ] = 15,
    format_type: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            help="Output formatting: table, json, or sarif.",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Destination file to save the generated report.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict/--no-strict",
            "--fail-on-anomaly/--no-fail-on-anomaly",
            help="Exit with non-zero status code if injection threats are detected.",
        ),
    ] = False,
) -> None:
    """Analyze a keystroke event stream to detect automated injection timing."""
    try:
        events = load_keystroke_events(events_file)
    except Exception as err:
        err_console.print(f"[bold red]Error loading keystroke events:[/bold red] {err}")
        raise typer.Exit(code=2) from err

    summary = analyze_keystrokes(
        events=events,
        threshold_ms=threshold_ms,
        window_size=window_size,
    )

    if format_type == OutputFormat.TABLE:
        if output:
            rendered = render_timing_table(summary, console=Console(record=True, color_system=None))
            write_output(rendered, output)
            console.print(f"[green]Table report successfully saved to:[/green] {output}")
        else:
            console.print(build_timing_summary_table(summary))
            if summary.has_threats:
                console.print()
                console.print(build_timing_anomalies_table(summary))
                console.print(
                    f"\n[bold red]ALERT:[/bold red] Detected {summary.anomaly_count} "
                    f"superhuman injection bursts (mean IKI < {summary.threshold_ms:.1f}ms)."
                )
            else:
                console.print(
                    "\n[bold green]STATUS OK:[/bold green] "
                    "All typing timing intervals appear natural."
                )
    elif format_type == OutputFormat.JSON:
        json_content = export_timing_json(summary)
        write_output(json_content, output)
        if output:
            console.print(f"[green]JSON report saved to:[/green] {output}")
    elif format_type == OutputFormat.SARIF:
        sarif_content = export_timing_sarif(summary, source_uri=str(events_file))
        write_output(sarif_content, output)
        if output:
            console.print(f"[green]SARIF v2.1.0 report saved to:[/green] {output}")

    if strict and summary.has_threats:
        raise typer.Exit(code=1)


@app.command(name="scan-usb")
def scan_usb(
    allowlist: Annotated[
        Path | None,
        typer.Option(
            "--allowlist",
            help="Path to JSON file containing approved USB device VID:PID pairs.",
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    format_type: Annotated[
        UsbOutputFormat,
        typer.Option(
            "--format",
            help="Output format: table, json, or sarif.",
        ),
    ] = UsbOutputFormat.TABLE,
    sysfs_path: Annotated[
        Path,
        typer.Option(
            "--sysfs-path",
            help="Root path to Linux USB sysfs devices directory.",
        ),
    ] = Path("/sys/bus/usb/devices"),
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Destination file to save the generated report.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict/--no-strict",
            "--fail-on-anomaly/--no-fail-on-anomaly",
            help="Exit with non-zero status code if unauthorized or anomalous devices are found.",
        ),
    ] = False,
) -> None:
    """Scan Linux sysfs USB descriptors for unauthorized devices or composite anomalies."""
    try:
        result = scan_sysfs_usb(sysfs_path=sysfs_path, allowlist_path=allowlist)
    except Exception as err:
        err_console.print(f"[bold red]Error during sysfs USB scan:[/bold red] {err}")
        raise typer.Exit(code=2) from err

    if format_type == UsbOutputFormat.TABLE:
        if output:
            rendered = render_usb_table(result, console=Console(record=True, color_system=None))
            write_output(rendered, output)
            console.print(f"[green]USB audit table saved to:[/green] {output}")
        else:
            console.print(build_usb_device_table(result))
            console.print()
            if result.has_threats:
                console.print(
                    f"[bold red]SECURITY THREATS DETECTED:[/bold red] "
                    f"{result.unauthorized_count} unauthorized, {result.anomaly_count} anomalies."
                )
            else:
                console.print(
                    f"[bold green]SYSFS SCAN CLEAN:[/bold green] All {result.total_scanned} "
                    "physical devices authorized."
                )
    elif format_type == UsbOutputFormat.JSON:
        json_content = export_usb_json(result)
        write_output(json_content, output)
        if output:
            console.print(f"[green]USB audit JSON report saved to:[/green] {output}")
    elif format_type == UsbOutputFormat.SARIF:
        sarif_content = export_usb_sarif(result)
        write_output(sarif_content, output)
        if output:
            console.print(f"[green]USB audit SARIF report saved to:[/green] {output}")

    if strict and result.has_threats:
        raise typer.Exit(code=1)


@app.command(name="simulate")
def simulate(
    profile: Annotated[
        SimulationProfile,
        typer.Option(
            "--profile",
            "-p",
            help="Simulation profile: 'human' for natural typing or 'injection' for BadUSB attack.",
        ),
    ] = SimulationProfile.HUMAN,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Destination JSON file to save the generated keystroke stream.",
        ),
    ] = None,
    count: Annotated[
        int,
        typer.Option(
            "--count",
            "-c",
            help="Number of simulated keystroke events to generate.",
        ),
    ] = 100,
    seed: Annotated[
        int | None,
        typer.Option(
            "--seed",
            help="Random seed for reproducible event generation.",
        ),
    ] = None,
) -> None:
    """Generate synthetic human or keystroke-injection event logs for testing."""
    try:
        events = simulate_events(
            profile=profile.value,
            count=count,
            output_path=output,
            seed=seed,
        )
    except Exception as err:
        err_console.print(f"[bold red]Simulation error:[/bold red] {err}")
        raise typer.Exit(code=2) from err

    if output:
        console.print(
            f"[bold green]Successfully generated {len(events)} '{profile.value}' "
            f"keystroke events to:[/bold green] {output}"
        )
    else:
        # Output raw JSON to stdout if no file destination specified
        import json

        print(json.dumps([ev.to_dict() for ev in events], indent=2))


if __name__ == "__main__":
    app()
