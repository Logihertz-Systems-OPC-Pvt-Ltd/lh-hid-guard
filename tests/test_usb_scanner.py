# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        tests.test_usb_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Linux sysfs USB descriptor scanner and allowlist filtering."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lh_hid_guard.scanner import load_allowlist, scan_sysfs_usb


def create_mock_sysfs_device(
    root: Path,
    bus_id: str,
    vendor_id: str,
    product_id: str,
    manufacturer: str,
    product: str,
    device_class: str = "00",
    interfaces: list[tuple[str, str, str, str]] | None = None,
) -> Path:
    """Helper to populate a simulated sysfs USB device directory."""
    dev_dir = root / bus_id
    dev_dir.mkdir(parents=True, exist_ok=True)
    (dev_dir / "idVendor").write_text(f"{vendor_id}\n", encoding="utf-8")
    (dev_dir / "idProduct").write_text(f"{product_id}\n", encoding="utf-8")
    (dev_dir / "manufacturer").write_text(f"{manufacturer}\n", encoding="utf-8")
    (dev_dir / "product").write_text(f"{product}\n", encoding="utf-8")
    (dev_dir / "bDeviceClass").write_text(f"{device_class}\n", encoding="utf-8")

    if interfaces:
        for iface_name, cls_code, subcls_code, proto_code in interfaces:
            iface_dir = dev_dir / iface_name
            iface_dir.mkdir(parents=True, exist_ok=True)
            (iface_dir / "bInterfaceClass").write_text(f"{cls_code}\n", encoding="utf-8")
            (iface_dir / "bInterfaceSubClass").write_text(f"{subcls_code}\n", encoding="utf-8")
            (iface_dir / "bInterfaceProtocol").write_text(f"{proto_code}\n", encoding="utf-8")

    return dev_dir


def test_load_allowlist_variants(tmp_path: Path) -> None:
    """Test loading different allowlist schemas and normalizing VID:PID."""
    # List of strings
    f1 = tmp_path / "allow1.json"
    f1.write_text(json.dumps(["046d:c52b", "17ef:608d"]), encoding="utf-8")
    assert load_allowlist(f1) == {"046d:c52b", "17ef:608d"}

    # Uppercase and short hex values
    f2 = tmp_path / "allow2.json"
    f2.write_text(json.dumps(["46D:C52B"]), encoding="utf-8")
    assert load_allowlist(f2) == {"046d:c52b"}

    # Dict with allowed_devices
    f3 = tmp_path / "allow3.json"
    f3.write_text(
        json.dumps(
            {
                "allowed_devices": [
                    {"vendor_id": "046d", "product_id": "c52b"},
                    {"vid": "17ef", "pid": "608d"},
                ]
            }
        ),
        encoding="utf-8",
    )
    assert load_allowlist(f3) == {"046d:c52b", "17ef:608d"}

    # Empty path
    assert load_allowlist(None) == set()

    # Non-existent file
    with pytest.raises(FileNotFoundError):
        load_allowlist(tmp_path / "missing.json")

    # Invalid structure
    f_invalid = tmp_path / "invalid.json"
    f_invalid.write_text(json.dumps({"unknown_key": 123}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_allowlist(f_invalid)


def test_scan_mocked_sysfs_devices(tmp_path: Path) -> None:
    """Test full sysfs scanning with authorized, unauthorized, and BadUSB devices."""
    sysfs_root = tmp_path / "usb_devices"
    sysfs_root.mkdir()

    # Device 1: Root Hub (should be identified as hub and excluded from threat counts)
    create_mock_sysfs_device(
        root=sysfs_root,
        bus_id="usb1",
        vendor_id="1d6b",
        product_id="0002",
        manufacturer="Linux Foundation",
        product="2.0 root hub",
        device_class="09",
    )

    # Device 2: Standard Authorized USB Keyboard (VID 046d, PID c52b)
    create_mock_sysfs_device(
        root=sysfs_root,
        bus_id="1-1",
        vendor_id="046d",
        product_id="c52b",
        manufacturer="Logitech",
        product="USB Receiver",
        interfaces=[("1-1:1.0", "03", "01", "01")],  # HID Keyboard
    )

    # Device 3: BadUSB Composite Storage + Keyboard Anomaly
    create_mock_sysfs_device(
        root=sysfs_root,
        bus_id="1-2",
        vendor_id="16c0",
        product_id="05df",
        manufacturer="Hak5",
        product="Rubber Ducky Flash",
        interfaces=[
            ("1-2:1.0", "03", "01", "01"),  # HID Keyboard
            ("1-2:1.1", "08", "06", "50"),  # Mass Storage
        ],
    )

    # Device 4: Unauthorized Generic USB Peripheral
    create_mock_sysfs_device(
        root=sysfs_root,
        bus_id="1-3",
        vendor_id="9999",
        product_id="8888",
        manufacturer="Unknown Corp",
        product="Suspicious Dongle",
        interfaces=[("1-3:1.0", "03", "00", "00")],
    )

    allowlist_file = tmp_path / "allowlist.json"
    # Allow Logitech keyboard and Hak5 VID:PID, but Hak5 still has composite anomaly
    allowlist_file.write_text(
        json.dumps(["046d:c52b", "16c0:05df"]),
        encoding="utf-8",
    )

    result = scan_sysfs_usb(sysfs_path=sysfs_root, allowlist_path=allowlist_file)

    assert result.total_scanned == 3  # Excludes root hub
    assert result.has_threats is True
    assert result.unauthorized_count == 1  # 9999:8888 is unauthorized

    # Find devices in results
    devices_by_bus = {d.bus_id: d for d in result.devices}

    logitech = devices_by_bus["1-1"]
    assert logitech.is_allowed is True
    assert logitech.has_composite_anomaly is False
    assert len(logitech.anomalies) == 0

    badusb = devices_by_bus["1-2"]
    assert badusb.is_allowed is True
    assert badusb.has_composite_anomaly is True
    assert any("COMPOSITE ANOMALY" in a for a in badusb.anomalies)

    unauth = devices_by_bus["1-3"]
    assert unauth.is_allowed is False
    assert any("UNAUTHORIZED DEVICE" in a for a in unauth.anomalies)


def test_scan_missing_sysfs_dir(tmp_path: Path) -> None:
    """Ensure non-existent sysfs path returns safe empty result without crashing."""
    missing = tmp_path / "does_not_exist"
    result = scan_sysfs_usb(sysfs_path=missing)
    assert result.total_scanned == 0
    assert result.has_threats is False
    assert len(result.devices) == 0
