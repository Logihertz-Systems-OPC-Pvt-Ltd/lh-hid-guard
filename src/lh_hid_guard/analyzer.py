# ==============================================================================
# Product:       lh-hid-guard (lh-hid)
# Module:        src.lh_hid_guard.analyzer
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Keystroke timing analyzer and automated injection anomaly detector.

This module analyzes keystroke event streams to compute rolling inter-keystroke
intervals (IKI), standard deviation, burst typing speed, and detects superhuman
typing patterns characteristic of hardware keystroke injection tools (e.g. BadUSB,
Rubber Ducky).
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from lh_hid_guard.models import (
    KeystrokeEvent,
    RollingWindowMetric,
    TimingAnalysisSummary,
    TimingInterval,
)


def load_keystroke_events(
    source: str | Path | list[dict[str, Any]] | dict[str, Any],
) -> list[KeystrokeEvent]:
    """Parse raw JSON log data or files into a sequence of KeystrokeEvent objects.

    Args:
        source: Path to JSON log file, raw JSON string, list of event dicts,
            or dict containing an 'events' key.

    Returns:
        List of KeystrokeEvent objects sorted chronologically by timestamp.

    Raises:
        ValueError: If data structure is invalid or cannot be parsed.
        FileNotFoundError: If the specified file path does not exist.
    """
    raw_data: Any
    if isinstance(source, (str, Path)):
        file_path = Path(source)
        if file_path.is_file():
            with file_path.open("r", encoding="utf-8") as f:
                raw_data = json.load(f)
        else:
            try:
                raw_data = json.loads(str(source))
            except json.JSONDecodeError as err:
                raise ValueError(f"Unable to parse input JSON: {err}") from err
    else:
        raw_data = source

    if isinstance(raw_data, dict):
        if "events" in raw_data and isinstance(raw_data["events"], list):
            raw_list = raw_data["events"]
        else:
            raise ValueError("Input JSON dictionary must contain an 'events' list key.")
    elif isinstance(raw_data, list):
        raw_list = raw_data
    else:
        raise ValueError("Invalid event data format: expected list or dict with 'events'.")

    events: list[KeystrokeEvent] = []
    for _idx, item in enumerate(raw_list):
        if not isinstance(item, dict):
            continue
        if "timestamp" not in item:
            continue
        try:
            ts = float(item["timestamp"])
        except (ValueError, TypeError):
            continue

        key = str(item.get("key", ""))
        action = str(item.get("action", "press")).lower()

        # Only process press/down events to measure inter-keystroke intervals accurately
        if action in ("release", "up"):
            continue

        events.append(KeystrokeEvent(timestamp=ts, key=key, action=action))

    events.sort(key=lambda ev: ev.timestamp)
    return events


def calculate_intervals(events: list[KeystrokeEvent]) -> list[TimingInterval]:
    """Compute inter-keystroke duration intervals between successive events.

    Detects whether timestamps are in seconds or milliseconds and converts
    all interval deltas to milliseconds.

    Args:
        events: Chronologically sorted list of keystroke events.

    Returns:
        List of calculated TimingInterval objects.
    """
    if len(events) < 2:
        return []

    # Heuristic: Check if raw timestamps are in seconds (e.g. ~1.7e9) or ms (> 1.7e11)
    # or relative timestamps. If the raw difference between adjacent timestamps
    # is consistently > 10.0, the input timestamps are likely already milliseconds.
    sample_diffs = [
        events[i].timestamp - events[i - 1].timestamp for i in range(1, min(len(events), 20))
    ]
    median_diff = sorted(sample_diffs)[len(sample_diffs) // 2] if sample_diffs else 0.0
    timestamps_already_ms = median_diff >= 10.0

    intervals: list[TimingInterval] = []
    for i in range(1, len(events)):
        prev_ev = events[i - 1]
        curr_ev = events[i]

        raw_delta = curr_ev.timestamp - prev_ev.timestamp
        # Prevent negative intervals if out-of-order events slipped through
        raw_delta = max(0.0, raw_delta)

        delta_ms = raw_delta if timestamps_already_ms else raw_delta * 1000.0

        intervals.append(
            TimingInterval(
                interval_index=i - 1,
                delta_ms=delta_ms,
                start_time=prev_ev.timestamp,
                end_time=curr_ev.timestamp,
                from_key=prev_ev.key,
                to_key=curr_ev.key,
            )
        )

    return intervals


def calculate_std_dev(values: list[float], mean_val: float) -> float:
    """Calculate sample standard deviation for a list of floating-point values.

    Args:
        values: Sequence of numerical values.
        mean_val: Precomputed mean of the values.

    Returns:
        Sample standard deviation, or 0.0 if fewer than 2 elements.
    """
    if len(values) < 2:
        return 0.0
    variance = sum((x - mean_val) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)


def analyze_keystrokes(
    events: list[KeystrokeEvent],
    threshold_ms: float = 8.0,
    window_size: int = 15,
) -> TimingAnalysisSummary:
    """Perform rolling-window statistical timing analysis on keystrokes.

    Flags superhuman typing speeds (< threshold_ms average IKI over a window)
    and anomalous near-zero jitter hardware injection patterns.

    Args:
        events: Keystroke event sequence.
        threshold_ms: Average IKI threshold in milliseconds below which typing
            is classified as superhuman hardware injection (default: 8.0ms).
        window_size: Number of intervals included in each sliding analysis window.

    Returns:
        TimingAnalysisSummary containing overall metrics and detected anomaly windows.
    """
    intervals = calculate_intervals(events)

    if not intervals:
        return TimingAnalysisSummary(
            total_events=len(events),
            total_intervals=0,
            overall_mean_iki_ms=0.0,
            overall_std_dev_iki_ms=0.0,
            min_iki_ms=0.0,
            max_iki_ms=0.0,
            overall_kps=0.0,
            overall_wpm=0.0,
            threshold_ms=threshold_ms,
            window_size=window_size,
            anomaly_count=0,
            anomalies=[],
            windows=[],
        )

    all_deltas = [interval.delta_ms for interval in intervals]
    total_delta = sum(all_deltas)
    overall_mean = total_delta / len(all_deltas)
    overall_std = calculate_std_dev(all_deltas, overall_mean)
    min_iki = min(all_deltas)
    max_iki = max(all_deltas)

    total_duration_sec = total_delta / 1000.0
    overall_kps = (len(events) / total_duration_sec) if total_duration_sec > 0 else 0.0
    overall_wpm = (overall_kps * 60.0) / 5.0

    windows: list[RollingWindowMetric] = []
    anomalies: list[RollingWindowMetric] = []

    # Adjust effective window size if interval stream is shorter than configured window
    effective_window = min(window_size, len(intervals))
    if effective_window < 1:
        effective_window = 1

    num_windows = len(intervals) - effective_window + 1
    for w_idx in range(num_windows):
        sub_intervals = intervals[w_idx : w_idx + effective_window]
        deltas = [item.delta_ms for item in sub_intervals]
        mean_val = sum(deltas) / len(deltas)
        std_val = calculate_std_dev(deltas, mean_val)
        min_val = min(deltas)
        max_val = max(deltas)

        burst_kps = (1000.0 / mean_val) if mean_val > 0.0 else 9999.0
        burst_wpm = (burst_kps * 60.0) / 5.0

        is_anomaly = False
        reasons: list[str] = []

        # Superhuman speed detection (< threshold_ms average over window)
        if mean_val < threshold_ms:
            is_anomaly = True
            reasons.append(
                f"Superhuman typing burst: average IKI {mean_val:.2f}ms "
                f"(< {threshold_ms:.1f}ms limit) at {burst_kps:.1f} keys/s ({burst_wpm:.1f} WPM)"
            )

        # Automated injection signature: high speed + near-zero jitter (constant delay loop)
        if mean_val < 25.0 and std_val < 0.8 and len(deltas) >= 5:
            is_anomaly = True
            reasons.append(
                f"Automated timing loop: ultra-low jitter (std dev {std_val:.2f}ms, "
                f"mean {mean_val:.2f}ms)"
            )

        metric = RollingWindowMetric(
            window_index=w_idx,
            start_interval_idx=w_idx,
            end_interval_idx=w_idx + effective_window - 1,
            start_time=sub_intervals[0].start_time,
            end_time=sub_intervals[-1].end_time,
            sample_count=len(sub_intervals),
            mean_iki_ms=mean_val,
            std_dev_iki_ms=std_val,
            min_iki_ms=min_val,
            max_iki_ms=max_val,
            burst_speed_kps=burst_kps,
            burst_speed_wpm=burst_wpm,
            is_anomaly=is_anomaly,
            reason="; ".join(reasons) if reasons else "",
        )

        windows.append(metric)
        if is_anomaly:
            anomalies.append(metric)

    return TimingAnalysisSummary(
        total_events=len(events),
        total_intervals=len(intervals),
        overall_mean_iki_ms=overall_mean,
        overall_std_dev_iki_ms=overall_std,
        min_iki_ms=min_iki,
        max_iki_ms=max_iki,
        overall_kps=overall_kps,
        overall_wpm=overall_wpm,
        threshold_ms=threshold_ms,
        window_size=window_size,
        anomaly_count=len(anomalies),
        anomalies=anomalies,
        windows=windows,
    )
