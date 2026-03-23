from __future__ import annotations

from statistics import mean, pstdev
from typing import Any, Dict, List


def analyze_behavioral_patterns(results: List[Dict[str, Any]], cfg) -> Dict[str, Any]:
    timing_signals: List[float] = []
    session_markers = 0
    for result in results:
        metadata = result.get("metadata", {})
        if "observed_intervals_ms" in metadata:
            timing_signals.extend(float(item) for item in metadata.get("observed_intervals_ms", []))
        if metadata.get("session_consistent"):
            session_markers += 1

    burst_score = sum(1 for item in timing_signals if item < cfg.behavioral.automation_jitter_floor_ms)
    jitter = pstdev(timing_signals) if len(timing_signals) > 1 else 0.0
    automation_probability = 0.0
    if timing_signals:
        cadence = mean(timing_signals)
        if cadence < 300 and jitter < cfg.behavioral.automation_jitter_floor_ms:
            automation_probability = min(0.95, 0.55 + (burst_score / max(len(timing_signals), 1)))

    return {
        "timing_samples": len(timing_signals),
        "mean_interval_ms": round(mean(timing_signals), 2) if timing_signals else None,
        "jitter_ms": round(jitter, 2),
        "burst_events": burst_score,
        "session_consistency_signals": session_markers,
        "automation_probability": round(automation_probability, 2),
        "assessment": "bot-like" if automation_probability >= 0.6 else "human-like",
    }
