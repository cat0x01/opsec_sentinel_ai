from __future__ import annotations

from dataclasses import replace

from opsec_sentinel_ai.config.settings import ModeConfig


MODE_PRESETS = {
    "normal": ModeConfig(name="normal"),
    "bugbounty": ModeConfig(
        name="bugbounty",
        scenario_confidence_floor=50,
        fingerprint_integrity_floor=65,
        live_monitoring_enabled=True,
        severity_bias={"critical": 22, "high": 14, "medium": 7, "low": 2, "info": 0},
    ),
    "darknet": ModeConfig(
        name="darknet",
        scenario_confidence_floor=65,
        fingerprint_integrity_floor=85,
        live_monitoring_enabled=True,
        severity_bias={"critical": 30, "high": 18, "medium": 10, "low": 4, "info": 0},
    ),
}


def resolve_mode_config(name: str) -> ModeConfig:
    normalized = (name or "normal").strip().lower()
    preset = MODE_PRESETS.get(normalized, MODE_PRESETS["normal"])
    return replace(preset)
