# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        src.lh_hid_guard.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models for keystroke timing events, USB descriptors, and detection findings.

This module provides strictly-typed dataclasses representing raw input events,
calculated rolling timing intervals, USB device hierarchy descriptors, and
security audit verdicts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class KeystrokeEvent:
    """Represents a discrete keystroke event recorded from a stream or log.

    Attributes:
        timestamp: Epoch timestamp in seconds (float) when the event occurred.
        key: The key identifier or character (e.g., 'a', 'ENTER').
        action: The event action type, typically 'press' or 'release'.
    """

    timestamp: float
    key: str = ""
    action: str = "press"

    def to_dict(self) -> dict[str, Any]:
        """Convert the keystroke event to a dictionary."""
        return asdict(self)


@dataclass(frozen=True)
class TimingInterval:
    """Represents the calculated duration between consecutive keystroke events.

    Attributes:
        interval_index: Zero-based sequence index of the interval.
        delta_ms: Duration between events in milliseconds.
        start_time: Starting timestamp of the interval.
        end_time: Ending timestamp of the interval.
        from_key: Key triggering the start of the interval.
        to_key: Key triggering the end of the interval.
    """

    interval_index: int
    delta_ms: float
    start_time: float
    end_time: float
    from_key: str = ""
    to_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert the timing interval to a dictionary."""
        return asdict(self)


@dataclass
class RollingWindowMetric:
    """Calculated statistical metrics for a sliding window of keystroke intervals.

    Attributes:
        window_index: Zero-based index of the sliding window.
        start_interval_idx: Starting index of the interval in the global stream.
        end_interval_idx: Ending index of the interval in the global stream.
        start_time: Window start timestamp.
        end_time: Window end timestamp.
        sample_count: Number of intervals evaluated in this window.
        mean_iki_ms: Average inter-keystroke interval in milliseconds.
        std_dev_iki_ms: Standard deviation of intervals in milliseconds.
        min_iki_ms: Minimum interval observed in this window in milliseconds.
        max_iki_ms: Maximum interval observed in this window in milliseconds.
        burst_speed_kps: Burst typing speed in keystrokes per second.
        burst_speed_wpm: Burst typing speed in estimated words per minute.
        is_anomaly: True if the metrics indicate automated keystroke injection.
        reason: Human-readable explanation of why this window is anomalous.
    """

    window_index: int
    start_interval_idx: int
    end_interval_idx: int
    start_time: float
    end_time: float
    sample_count: int
    mean_iki_ms: float
    std_dev_iki_ms: float
    min_iki_ms: float
    max_iki_ms: float
    burst_speed_kps: float
    burst_speed_wpm: float
    is_anomaly: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert the rolling window metric to a dictionary."""
        return asdict(self)


@dataclass
class TimingAnalysisSummary:
    """Comprehensive summary of keystroke stream timing analysis.

    Attributes:
        total_events: Total keystroke events processed.
        total_intervals: Total calculated intervals between consecutive keystrokes.
        overall_mean_iki_ms: Mean IKI across the entire stream in milliseconds.
        overall_std_dev_iki_ms: Standard deviation of IKI across the entire stream.
        min_iki_ms: Absolute minimum IKI recorded in milliseconds.
        max_iki_ms: Absolute maximum IKI recorded in milliseconds.
        overall_kps: Keystrokes per second over the entire capture period.
        overall_wpm: Words per minute over the entire capture period.
        threshold_ms: Superhuman injection threshold configured for evaluation.
        window_size: Window size in intervals used for rolling analysis.
        anomaly_count: Count of anomalous windows detected.
        anomalies: List of rolling window metrics identified as anomalies.
        windows: List of all evaluated rolling window metrics.
    """

    total_events: int
    total_intervals: int
    overall_mean_iki_ms: float
    overall_std_dev_iki_ms: float
    min_iki_ms: float
    max_iki_ms: float
    overall_kps: float
    overall_wpm: float
    threshold_ms: float
    window_size: int
    anomaly_count: int = 0
    anomalies: list[RollingWindowMetric] = field(default_factory=list)
    windows: list[RollingWindowMetric] = field(default_factory=list)

    @property
    def has_threats(self) -> bool:
        """Return True if any keystroke injection anomalies were detected."""
        return self.anomaly_count > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert the timing analysis summary to a dictionary."""
        return {
            "total_events": self.total_events,
            "total_intervals": self.total_intervals,
            "overall_mean_iki_ms": round(self.overall_mean_iki_ms, 3),
            "overall_std_dev_iki_ms": round(self.overall_std_dev_iki_ms, 3),
            "min_iki_ms": round(self.min_iki_ms, 3),
            "max_iki_ms": round(self.max_iki_ms, 3),
            "overall_kps": round(self.overall_kps, 2),
            "overall_wpm": round(self.overall_wpm, 2),
            "threshold_ms": self.threshold_ms,
            "window_size": self.window_size,
            "anomaly_count": self.anomaly_count,
            "has_threats": self.has_threats,
            "anomalies": [a.to_dict() for a in self.anomalies],
        }


@dataclass
class UsbInterface:
    """Represents a single interface descriptor under a Linux sysfs USB device.

    Attributes:
        interface_name: Directory name of the interface (e.g., '1-1:1.0').
        class_code: Hex string of bInterfaceClass (e.g., '03' for HID).
        subclass_code: Hex string of bInterfaceSubClass.
        protocol_code: Hex string of bInterfaceProtocol (e.g., '01' for Keyboard).
        driver: Name of the currently bound kernel driver, if any.
    """

    interface_name: str
    class_code: str
    subclass_code: str
    protocol_code: str
    driver: str = ""

    @property
    def is_hid(self) -> bool:
        """Check if this interface is a Human Interface Device (HID)."""
        return self.class_code.lower() == "03"

    @property
    def is_keyboard(self) -> bool:
        """Check if this interface explicitly declares a Keyboard protocol."""
        return self.is_hid and (self.protocol_code.lower() in ("01", "1"))

    @property
    def is_mass_storage(self) -> bool:
        """Check if this interface is USB Mass Storage."""
        return self.class_code.lower() == "08"

    def to_dict(self) -> dict[str, Any]:
        """Convert interface descriptor to dictionary."""
        return asdict(self)


@dataclass
class UsbDevice:
    """Represents a physical or virtual USB device discovered in Linux sysfs.

    Attributes:
        bus_id: Device sysfs identifier (e.g., '1-1.2').
        sysfs_path: Absolute filesystem path to the device directory.
        vendor_id: 4-digit hexadecimal USB Vendor ID (VID).
        product_id: 4-digit hexadecimal USB Product ID (PID).
        manufacturer: Manufacturer descriptor string.
        product: Product descriptor string.
        serial: Serial number descriptor string.
        device_class: 2-digit hex device class code.
        interfaces: List of parsed child USB interfaces.
        is_allowed: Whether this VID:PID is present in the approved allowlist.
        has_composite_anomaly: True if device exposes both storage and keyboard interfaces.
        anomalies: List of specific security findings or anomaly descriptions.
    """

    bus_id: str
    sysfs_path: str
    vendor_id: str
    product_id: str
    manufacturer: str = ""
    product: str = ""
    serial: str = ""
    device_class: str = ""
    interfaces: list[UsbInterface] = field(default_factory=list)
    is_allowed: bool = True
    has_composite_anomaly: bool = False
    anomalies: list[str] = field(default_factory=list)

    @property
    def vid_pid(self) -> str:
        """Return formatted Vendor ID:Product ID string."""
        return f"{self.vendor_id.lower()}:{self.product_id.lower()}"

    @property
    def is_hub(self) -> bool:
        """Check if device is a root or intermediate USB hub."""
        return self.device_class.lower() == "09"

    @property
    def has_threats(self) -> bool:
        """Return True if device is unauthorized or exhibits security anomalies."""
        return not self.is_allowed or self.has_composite_anomaly or len(self.anomalies) > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert USB device object to dictionary."""
        return {
            "bus_id": self.bus_id,
            "sysfs_path": self.sysfs_path,
            "vid_pid": self.vid_pid,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "manufacturer": self.manufacturer,
            "product": self.product,
            "serial": self.serial,
            "device_class": self.device_class,
            "is_hub": self.is_hub,
            "is_allowed": self.is_allowed,
            "has_composite_anomaly": self.has_composite_anomaly,
            "anomalies": self.anomalies,
            "has_threats": self.has_threats,
            "interfaces": [iface.to_dict() for iface in self.interfaces],
        }


@dataclass
class UsbScanResult:
    """Aggregated results from scanning sysfs USB devices against an allowlist.

    Attributes:
        sysfs_path: Root sysfs path scanned.
        allowlist_path: Path to allowlist file used, if any.
        total_scanned: Total physical/virtual USB devices discovered (excluding hubs).
        authorized_count: Total devices matching the allowlist with no anomalies.
        unauthorized_count: Devices missing from allowlist.
        anomaly_count: Total security anomalies flagged (e.g. composite storage+keyboard).
        devices: Full list of discovered devices.
    """

    sysfs_path: str
    allowlist_path: str = ""
    total_scanned: int = 0
    authorized_count: int = 0
    unauthorized_count: int = 0
    anomaly_count: int = 0
    devices: list[UsbDevice] = field(default_factory=list)

    @property
    def has_threats(self) -> bool:
        """Return True if any unauthorized devices or anomalies were detected."""
        return self.unauthorized_count > 0 or self.anomaly_count > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "sysfs_path": self.sysfs_path,
            "allowlist_path": self.allowlist_path,
            "total_scanned": self.total_scanned,
            "authorized_count": self.authorized_count,
            "unauthorized_count": self.unauthorized_count,
            "anomaly_count": self.anomaly_count,
            "has_threats": self.has_threats,
            "devices": [dev.to_dict() for dev in self.devices],
        }
