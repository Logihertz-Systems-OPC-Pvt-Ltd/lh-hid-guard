# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        tests.test_simulator
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for synthetic human vs. keystroke-injection event generator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lh_hid_guard.analyzer import calculate_intervals
from lh_hid_guard.simulator import (
    generate_human_stream,
    generate_injection_stream,
    simulate_events,
)


def test_generate_human_stream_properties() -> None:
    """Verify characteristics of generated human typing stream."""
    events = generate_human_stream(count=50, seed=123)
    assert len(events) == 50

    intervals = calculate_intervals(events)
    assert len(intervals) == 49

    deltas = [i.delta_ms for i in intervals]
    mean_delta = sum(deltas) / len(deltas)

    # Human average IKI should be physically realistic (> 80ms)
    assert mean_delta > 80.0
    # Human minimum should not be zero or impossibly fast
    assert min(deltas) >= 35.0


def test_generate_injection_stream_properties() -> None:
    """Verify characteristics of generated keystroke injection stream."""
    events = generate_injection_stream(count=50, seed=123, mean_delay_ms=3.5)
    assert len(events) == 50

    intervals = calculate_intervals(events)
    assert len(intervals) == 49

    deltas = [i.delta_ms for i in intervals]
    mean_delta = sum(deltas) / len(deltas)

    # Injection stream must be superhuman (< 8.0ms)
    assert mean_delta < 8.0
    assert 2.5 <= mean_delta <= 4.5


def test_simulate_events_output_file(tmp_path: Path) -> None:
    """Test saving simulation to file and checking JSON output."""
    out_file = tmp_path / "simulated.json"
    events = simulate_events(profile="injection", count=30, output_path=out_file, seed=42)

    assert len(events) == 30
    assert out_file.is_file()

    loaded = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(loaded) == 30
    assert "timestamp" in loaded[0]
    assert "key" in loaded[0]
    assert loaded[0]["action"] == "press"


def test_simulate_events_invalid_profile() -> None:
    """Ensure invalid profile names raise a descriptive ValueError."""
    with pytest.raises(ValueError, match="Invalid profile"):
        simulate_events(profile="alien_super_intelligence")
