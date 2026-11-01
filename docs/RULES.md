# Security Rules Reference: lh-hid-guard

An enterprise usb hid keystroke-injection & hardware defense cli developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-hid-guard`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-HID-001` | `CRITICAL` | Timing Anomaly | Superhuman Keystroke Injection Timing Anomaly Detected |
| `LH-HID-002` | `HIGH` | Device Allowlist | Unauthorized USB HID Device VID:PID Detected |
| `LH-HID-003` | `CRITICAL` | Composite Device | Composite USB Device Anomaly: Keyboard Bundled with Mass Storage |
| `LH-HID-004` | `HIGH` | Velocity Anomaly | Burst Typing Velocity Exceeding Biological Limits |
| `LH-HID-005` | `HIGH` | Timing Anomaly | Zero Keystroke Timing Variance in Stream |
| `LH-HID-006` | `MEDIUM` | Device Governance | Unrecognized USB Vendor or Missing Serial in Sysfs |
| `LH-HID-007` | `HIGH` | Device Anomaly | Rapid USB Disconnect/Reconnect Cycle Detected |
| `LH-HID-008` | `MEDIUM` | Protocol Anomaly | Unauthorized HID Interface Claiming Boot Protocol |
| `LH-HID-009` | `LOW` | Governance | Missing or Stale USB Device Allowlist Configuration |
| `LH-HID-010` | `LOW` | Telemetry | Incomplete Keystroke Stream Telemetry Window |

---

## Granular Rule Specifications

### `LH-HID-001`: Superhuman Keystroke Injection Timing Anomaly Detected

- **Severity**: `CRITICAL`
- **Category**: `Timing Anomaly`
- **Description**: Rolling inter-keystroke interval (IKI) dropped below 8.0ms human limit, indicating hardware injection.
- **Remediation**: Block automated keystroke stream, disconnect unauthorized USB device, and lock workstation session.

---

### `LH-HID-002`: Unauthorized USB HID Device VID:PID Detected

- **Severity**: `HIGH`
- **Category**: `Device Allowlist`
- **Description**: Connected USB device VID:PID not present in approved enterprise peripheral allowlist.
- **Remediation**: Authorize only company-approved USB keyboards via udev rules and USBGuard policy.

---

### `LH-HID-003`: Composite USB Device Anomaly: Keyboard Bundled with Mass Storage

- **Severity**: `CRITICAL`
- **Category**: `Composite Device`
- **Description**: Single USB device enumerates both a keyboard descriptor and a mass storage or network interface.
- **Remediation**: Configure udev to reject composite USB peripherals that advertise HID combined with storage.

---

### `LH-HID-004`: Burst Typing Velocity Exceeding Biological Limits

- **Severity**: `HIGH`
- **Category**: `Velocity Anomaly`
- **Description**: Sustained typing velocity exceeding 300 words per minute over an evaluation window.
- **Remediation**: Rate-limit console keystroke processing and prompt user for physical verification.

---

### `LH-HID-005`: Zero Keystroke Timing Variance in Stream

- **Severity**: `HIGH`
- **Category**: `Timing Anomaly`
- **Description**: Keystroke intervals have zero or near-zero standard deviation, characteristic of microcontrollers.
- **Remediation**: Flag synthetic keystroke injection hardware and terminate active terminal session.

---

### `LH-HID-006`: Unrecognized USB Vendor or Missing Serial in Sysfs

- **Severity**: `MEDIUM`
- **Category**: `Device Governance`
- **Description**: USB descriptor has unknown vendor ID 0000 or omitted serial number string.
- **Remediation**: Enforce strict USB descriptor validation and reject malformed USB peripheral descriptors.

---

### `LH-HID-007`: Rapid USB Disconnect/Reconnect Cycle Detected

- **Severity**: `HIGH`
- **Category**: `Device Anomaly`
- **Description**: Repeated USB disconnect and reconnect cycles within seconds indicative of enumeration attack.
- **Remediation**: Temporarily disable USB port upon rapid flap detection to prevent brute-force enumeration.

---

### `LH-HID-008`: Unauthorized HID Interface Claiming Boot Protocol

- **Severity**: `MEDIUM`
- **Category**: `Protocol Anomaly`
- **Description**: Non-keyboard peripheral advertising boot protocol keyboard descriptor to bypass driver checks.
- **Remediation**: Validate HID report descriptors against actual physical input capabilities.

---

### `LH-HID-009`: Missing or Stale USB Device Allowlist Configuration

- **Severity**: `LOW`
- **Category**: `Governance`
- **Description**: Device allowlist file missing or older than 90 days without administrative update.
- **Remediation**: Update USB device allowlist regularly with current enterprise inventory assets.

---

### `LH-HID-010`: Incomplete Keystroke Stream Telemetry Window

- **Severity**: `LOW`
- **Category**: `Telemetry`
- **Description**: Telemetry stream contains insufficient keystroke events to compute statistical baseline.
- **Remediation**: Ensure minimum evaluation window size of at least 15 keystrokes for reliable analysis.

---
