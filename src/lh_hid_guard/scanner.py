# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        src.lh_hid_guard.scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Linux sysfs USB device descriptor scanner and allowlist auditor.

This module inspects Linux USB device sysfs trees (/sys/bus/usb/devices) to
extract VID:PID identifiers, manufacturer metadata, and interface descriptors.
It flags unauthorized hardware against an approved allowlist and identifies
anomalies such as composite Storage + Keyboard devices typical of BadUSB hardware.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lh_hid_guard.models import UsbDevice, UsbInterface, UsbScanResult


def _read_sysfs_attr(path: Path, attr_name: str) -> str:
    """Safely read and strip a text attribute from a sysfs directory.

    Args:
        path: Parent directory path in sysfs.
        attr_name: Name of the attribute file (e.g. 'idVendor').

    Returns:
        Stripped string contents or empty string if unreadable.
    """
    attr_file = path / attr_name
    try:
        if attr_file.is_file():
            return attr_file.read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, PermissionError):
        pass
    return ""


def load_allowlist(allowlist_path: str | Path | None) -> set[str]:
    """Load and normalize an approved USB device allowlist from a JSON file.

    Supports:
        - List of strings: ["046d:c52b", "17ef:608d"]
        - List of dicts: [{"vendor_id": "046d", "product_id": "c52b"}, ...]
        - Dict with 'allowed_devices': {"allowed_devices": [{"vendor_id": ...}]}
        - Dict with 'allowlist': {"allowlist": ["046d:c52b"]}

    Args:
        allowlist_path: Filesystem path to the JSON allowlist file.

    Returns:
        Set of lowercase normalized 'vid:pid' strings.

    Raises:
        ValueError: If JSON syntax is invalid or structure is unrecognized.
        FileNotFoundError: If the allowlist path does not exist.
    """
    if not allowlist_path:
        return set()

    path = Path(allowlist_path)
    if not path.is_file():
        raise FileNotFoundError(f"Allowlist file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    allowed_set: set[str] = set()

    def _normalize_pair(vid: str, pid: str) -> str:
        v = vid.strip().lower().zfill(4)
        p = pid.strip().lower().zfill(4)
        return f"{v}:{p}"

    raw_items: list[Any] = []
    if isinstance(data, list):
        raw_items = data
    elif isinstance(data, dict):
        if "allowed_devices" in data and isinstance(data["allowed_devices"], list):
            raw_items = data["allowed_devices"]
        elif "allowlist" in data and isinstance(data["allowlist"], list):
            raw_items = data["allowlist"]
        elif "devices" in data and isinstance(data["devices"], list):
            raw_items = data["devices"]
        else:
            raise ValueError(
                "Unrecognized allowlist JSON schema. Expected list or dict with 'allowed_devices'."
            )
    else:
        raise ValueError("Invalid allowlist JSON: root must be a list or object.")

    for item in raw_items:
        if isinstance(item, str):
            parts = item.split(":")
            if len(parts) == 2:
                allowed_set.add(_normalize_pair(parts[0], parts[1]))
        elif isinstance(item, dict):
            vid = str(item.get("vendor_id") or item.get("vid") or "")
            pid = str(item.get("product_id") or item.get("pid") or "")
            if vid and pid:
                allowed_set.add(_normalize_pair(vid, pid))

    return allowed_set


def parse_usb_interfaces(device_path: Path) -> list[UsbInterface]:
    """Parse interface descriptors from subdirectories under a sysfs USB device.

    Args:
        device_path: Path to the device directory in sysfs (e.g. /sys/bus/usb/devices/1-1).

    Returns:
        List of UsbInterface objects representing endpoints of the device.
    """
    interfaces: list[UsbInterface] = []
    try:
        entries = sorted(device_path.iterdir())
    except (OSError, PermissionError):
        return []

    for entry in entries:
        if not entry.is_dir():
            continue
        # Interface directories have names containing a colon (e.g., '1-1:1.0')
        if ":" not in entry.name:
            continue

        class_code = _read_sysfs_attr(entry, "bInterfaceClass")
        subclass_code = _read_sysfs_attr(entry, "bInterfaceSubClass")
        protocol_code = _read_sysfs_attr(entry, "bInterfaceProtocol")

        driver = ""
        driver_symlink = entry / "driver"
        try:
            if driver_symlink.is_symlink():
                driver = driver_symlink.resolve().name
        except (OSError, PermissionError):
            pass

        interfaces.append(
            UsbInterface(
                interface_name=entry.name,
                class_code=class_code.zfill(2) if class_code else "",
                subclass_code=subclass_code.zfill(2) if subclass_code else "",
                protocol_code=protocol_code.zfill(2) if protocol_code else "",
                driver=driver,
            )
        )

    return interfaces


def scan_sysfs_usb(
    sysfs_path: str | Path = "/sys/bus/usb/devices",
    allowlist_path: str | Path | None = None,
) -> UsbScanResult:
    """Scan Linux sysfs USB devices and evaluate against an authorized allowlist.

    Identifies:
        - Unauthorized USB devices (missing from allowlist).
        - Composite Storage + Keyboard anomalies (BadUSB / keystroke injection vector).

    Args:
        sysfs_path: Root sysfs directory to scan (default: /sys/bus/usb/devices).
        allowlist_path: Path to JSON allowlist file.

    Returns:
        UsbScanResult containing evaluated device inventory and threat counts.
    """
    root_path = Path(sysfs_path)
    allowlist: set[str] = set()
    if allowlist_path:
        allowlist = load_allowlist(allowlist_path)

    if not root_path.exists() or not root_path.is_dir():
        return UsbScanResult(
            sysfs_path=str(root_path),
            allowlist_path=str(allowlist_path or ""),
            total_scanned=0,
            authorized_count=0,
            unauthorized_count=0,
            anomaly_count=0,
            devices=[],
        )

    devices: list[UsbDevice] = []
    try:
        entries = sorted(root_path.iterdir())
    except (OSError, PermissionError):
        entries = []

    for entry in entries:
        # Ignore interface nodes at root level (which contain ':')
        if ":" in entry.name:
            continue

        id_vendor = _read_sysfs_attr(entry, "idVendor")
        id_product = _read_sysfs_attr(entry, "idProduct")

        # Must have at least idVendor or idProduct to be a valid USB device
        if not id_vendor and not id_product:
            continue

        manufacturer = _read_sysfs_attr(entry, "manufacturer")
        product = _read_sysfs_attr(entry, "product")
        serial = _read_sysfs_attr(entry, "serial")
        device_class = _read_sysfs_attr(entry, "bDeviceClass")

        interfaces = parse_usb_interfaces(entry)

        # Detect composite Storage + Keyboard anomaly
        has_keyboard = any(
            iface.is_keyboard or (iface.is_hid and not iface.protocol_code) for iface in interfaces
        )
        has_storage = any(iface.is_mass_storage for iface in interfaces)
        composite_anomaly = has_keyboard and has_storage

        anomalies: list[str] = []
        if composite_anomaly:
            anomalies.append(
                "COMPOSITE ANOMALY: Device exposes both Mass Storage (08) and "
                "Keyboard HID (03) interfaces (characteristic of BadUSB / "
                "keystroke injection hardware)."
            )

        norm_vid = id_vendor.lower().zfill(4)
        norm_pid = id_product.lower().zfill(4)
        vid_pid = f"{norm_vid}:{norm_pid}"

        is_hub = device_class == "09" or entry.name.startswith("usb")

        # Allowlist check: If allowlist is configured, non-hub devices must match
        if allowlist and not is_hub:
            is_allowed = vid_pid in allowlist
            if not is_allowed:
                anomalies.append(
                    f"UNAUTHORIZED DEVICE: VID:PID '{vid_pid}' is not in approved allowlist."
                )
        else:
            is_allowed = True

        dev = UsbDevice(
            bus_id=entry.name,
            sysfs_path=str(entry.resolve()),
            vendor_id=norm_vid,
            product_id=norm_pid,
            manufacturer=manufacturer,
            product=product,
            serial=serial,
            device_class=device_class,
            interfaces=interfaces,
            is_allowed=is_allowed,
            has_composite_anomaly=composite_anomaly,
            anomalies=anomalies,
        )
        devices.append(dev)

    # Calculate summary metrics (excluding hubs from unauthorized counts)
    physical_devices = [d for d in devices if not d.is_hub]
    authorized_count = sum(
        1 for d in physical_devices if d.is_allowed and not d.has_composite_anomaly
    )
    unauthorized_count = sum(1 for d in physical_devices if not d.is_allowed)
    anomaly_count = sum(len(d.anomalies) for d in devices)

    return UsbScanResult(
        sysfs_path=str(root_path),
        allowlist_path=str(allowlist_path or ""),
        total_scanned=len(physical_devices),
        authorized_count=authorized_count,
        unauthorized_count=unauthorized_count,
        anomaly_count=anomaly_count,
        devices=devices,
    )
