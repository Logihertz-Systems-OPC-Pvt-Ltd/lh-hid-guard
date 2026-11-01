# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        src.lh_hid_guard.__init__
# Role:          Package Initialization & Public API Declarations
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""lh-hid-guard: Defensive Linux endpoint tool detecting automated keystroke-injection hardware.

Developed by Logihertz Systems OPC Pvt Ltd.
Analyzes USB HID device descriptors and inter-keystroke timing intervals (IKI).
"""

from __future__ import annotations

from lh_hid_guard.analyzer import analyze_keystrokes, calculate_intervals, load_keystroke_events
from lh_hid_guard.models import (
    KeystrokeEvent,
    RollingWindowMetric,
    TimingAnalysisSummary,
    TimingInterval,
    UsbDevice,
    UsbInterface,
    UsbScanResult,
)
from lh_hid_guard.scanner import load_allowlist, scan_sysfs_usb
from lh_hid_guard.simulator import generate_human_stream, generate_injection_stream, simulate_events

__version__ = "0.1.0"
__author__ = "Logihertz Systems OPC Pvt Ltd"
__all__ = [
    "KeystrokeEvent",
    "RollingWindowMetric",
    "TimingAnalysisSummary",
    "TimingInterval",
    "UsbDevice",
    "UsbInterface",
    "UsbScanResult",
    "analyze_keystrokes",
    "calculate_intervals",
    "generate_human_stream",
    "generate_injection_stream",
    "load_allowlist",
    "load_keystroke_events",
    "scan_sysfs_usb",
    "simulate_events",
]
