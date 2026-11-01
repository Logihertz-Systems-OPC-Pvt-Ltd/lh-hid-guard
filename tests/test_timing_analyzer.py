# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        tests.test_timing_analyzer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for keystroke timing analyzer and IKI calculations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lh_hid_guard.analyzer import (
    analyze_keystrokes,
    calculate_intervals,
    calculate_std_dev,
    load_keystroke_events,
)
from lh_hid_guard.models import KeystrokeEvent
from lh_hid_guard.simulator import generate_human_stream, generate_injection_stream


def test_calculate_std_dev() -> None:
    """Test sample standard deviation calculation edge cases."""
    assert calculate_std_dev([], 0.0) == 0.0
    assert calculate_std_dev([5.0], 5.0) == 0.0
    values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
    mean = sum(values) / len(values)
    std = calculate_std_dev(values, mean)
    assert 2.0 < std < 2.2


def test_calculate_intervals_seconds_and_ms() -> None:
    """Verify calculation of intervals from seconds and millisecond timestamps."""
    # Timestamps in seconds
    events_sec = [
        KeystrokeEvent(timestamp=100.000, key="a"),
        KeystrokeEvent(timestamp=100.050, key="b"),
        KeystrokeEvent(timestamp=100.120, key="c"),
    ]
    intervals = calculate_intervals(events_sec)
    assert len(intervals) == 2
    assert abs(intervals[0].delta_ms - 50.0) < 0.001
    assert abs(intervals[1].delta_ms - 70.0) < 0.001

    # Timestamps in milliseconds
    events_ms = [
        KeystrokeEvent(timestamp=1000.0, key="a"),
        KeystrokeEvent(timestamp=1045.0, key="b"),
        KeystrokeEvent(timestamp=1100.0, key="c"),
    ]
    intervals_ms = calculate_intervals(events_ms)
    assert len(intervals_ms) == 2
    assert abs(intervals_ms[0].delta_ms - 45.0) < 0.001
    assert abs(intervals_ms[1].delta_ms - 55.0) < 0.001

    # Edge cases
    assert calculate_intervals([]) == []
    assert calculate_intervals([events_sec[0]]) == []


def test_load_keystroke_events_formats(tmp_path: Path) -> None:
    """Test loading events from diverse sources and filtering release events."""
    data = [
        {"timestamp": 1.0, "key": "a", "action": "press"},
        {"timestamp": 1.05, "key": "a", "action": "release"},  # Should be skipped
        {"timestamp": 1.1, "key": "b", "action": "press"},
    ]
    # Direct list
    events = load_keystroke_events(data)
    assert len(events) == 2
    assert events[0].key == "a"
    assert events[1].key == "b"

    # Dictionary with "events" key
    dict_data = {"events": data}
    events2 = load_keystroke_events(dict_data)
    assert len(events2) == 2

    # JSON File
    json_file = tmp_path / "events.json"
    json_file.write_text(json.dumps(dict_data), encoding="utf-8")
    events3 = load_keystroke_events(json_file)
    assert len(events3) == 2

    # Invalid sources
    with pytest.raises(ValueError):
        load_keystroke_events("invalid-json-string-not-json")
    with pytest.raises(ValueError):
        load_keystroke_events({"wrong_key": []})


def test_analyze_human_vs_injection() -> None:
    """Verify that human stream is clean and injection stream triggers superhuman alert."""
    human_events = generate_human_stream(count=60, seed=42)
    injection_events = generate_injection_stream(count=60, seed=42, mean_delay_ms=3.0)

    # Human analysis
    human_summary = analyze_keystrokes(human_events, threshold_ms=8.0, window_size=15)
    assert not human_summary.has_threats
    assert human_summary.anomaly_count == 0
    assert human_summary.overall_mean_iki_ms > 40.0

    # Injection analysis
    injection_summary = analyze_keystrokes(injection_events, threshold_ms=8.0, window_size=15)
    assert injection_summary.has_threats
    assert injection_summary.anomaly_count > 0
    assert injection_summary.overall_mean_iki_ms < 8.0
    assert "Superhuman" in injection_summary.anomalies[0].reason


def test_empty_or_single_event_analysis() -> None:
    """Ensure graceful handling when events stream is empty or too short."""
    summary_empty = analyze_keystrokes([])
    assert summary_empty.total_events == 0
    assert summary_empty.total_intervals == 0
    assert not summary_empty.has_threats

    summary_single = analyze_keystrokes([KeystrokeEvent(timestamp=1.0, key="x")])
    assert summary_single.total_events == 1
    assert summary_single.total_intervals == 0
    assert not summary_single.has_threats
