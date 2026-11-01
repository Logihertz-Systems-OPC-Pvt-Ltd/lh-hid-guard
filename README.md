# lh-hid-guard

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-hid-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-hid-guard/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise usb & hardware peripheral defense developed by **Logihertz Systems (OPC) Private Limited**.

Analyzes Linux udev rules, USB device descriptors (lsusb/sysfs snapshots), and USBGuard policies to detect BadUSB keystroke injection vectors, unauthorized HID interfaces, and unrestricted DMA/mass-storage classes.

---

## Key Features

- **Inter-Keystroke Interval (IKI) Timing Analysis**: Calculates rolling IKI variance and flags sub-human typing speeds (< 8.0ms) indicative of microcontroller hardware injection.
- **Linux Sysfs Peripheral Auditing**: Scans `/sys/bus/usb/devices/` against approved device allowlists to flag unauthorized VID:PID pairs.
- **Composite Device Anomaly Detection**: Detects stealthy composite USB devices advertising keyboard descriptors bundled with mass storage or network adapters.
- **Synthetic Telemetry Simulation**: Built-in event stream simulator to generate human typing vs. BadUSB injection streams for testing.
- **Multi-Format Reporting**: Outputs rich terminal tables, structured JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-HID-001` | `CRITICAL` | Superhuman keystroke injection timing anomaly detected (IKI < 8.0ms over window) |
| `LH-HID-002` | `HIGH` | Unauthorized USB HID device VID:PID not present in approved device allowlist |
| `LH-HID-003` | `CRITICAL` | Composite USB device anomaly: keyboard descriptor bundled with mass storage |
| `LH-HID-004` | `HIGH` | Burst typing velocity exceeding biological human typing limits |
| `LH-HID-005` | `HIGH` | Zero keystroke timing variance or near-zero standard deviation in typing stream |
| `LH-HID-006` | `MEDIUM` | Unrecognized USB vendor or missing serial descriptor in sysfs hierarchy |
| `LH-HID-007` | `HIGH` | Rapid USB disconnect/reconnect cycle indicative of BadUSB enumeration |
| `LH-HID-008` | `MEDIUM` | Unauthorized HID interface claiming boot protocol keyboard descriptor |
| `LH-HID-009` | `LOW` | Missing or stale USB device allowlist configuration |
| `LH-HID-010` | `LOW` | Incomplete keystroke stream telemetry or truncated timestamp window |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-hid-guard.git
cd lh-hid-guard

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-guard` (also accessible via `lh-guard`).

```bash
# Analyze a keystroke timing event stream for injection
lh-guard analyze-log events.json --threshold-ms 8.0

# Scan system USB devices against an approved allowlist
lh-guard scan-usb --allowlist allowlist.json

# Generate simulated BadUSB keystroke injection logs for testing
lh-guard simulate --profile injection --output badusb.json

# Export findings to OASIS SARIF v2.1.0
lh-guard analyze-log events.json --format sarif --output hid-audit.sarif
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
