from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(slots=True)
class EngineConfig:
    max_concurrency: int = 6
    plugin_directories: List[str] = field(default_factory=list)


@dataclass(slots=True)
class NetworkConfig:
    tor_check_url: Optional[str] = None
    dns_expect_private: bool = False
    proxy_required: bool = False


@dataclass(slots=True)
class BrowserConfig:
    enabled: bool = True
    user_agent: str = "OPSEC-Sentinel-AI"
    viewport_width: int = 1280
    viewport_height: int = 720


@dataclass(slots=True)
class SystemConfig:
    open_ports_common: List[int] = field(default_factory=lambda: [22, 80, 443, 445, 3306, 5432, 6379, 27017])
    suspicious_path_indicators: List[str] = field(
        default_factory=lambda: ["/tmp", "/var/tmp", "/dev/shm", "\\AppData\\Local\\Temp"]
    )


@dataclass(slots=True)
class FingerprintConfig:
    geoip_url: Optional[str] = None
    header_check_url: Optional[str] = None
    allowed_timezone_drift_hours: int = 3


@dataclass(slots=True)
class MonitoringConfig:
    enabled: bool = False
    interval_seconds: int = 5
    alert_on_ipv6: bool = True
    alert_on_non_private_dns: bool = True
    track_processes: bool = True


@dataclass(slots=True)
class BehavioralConfig:
    burst_threshold: int = 12
    automation_jitter_floor_ms: int = 75
    session_gap_threshold_seconds: int = 1800


@dataclass(slots=True)
class ReconConfig:
    enabled: bool = True
    reputation_sources: List[str] = field(default_factory=lambda: ["local_heuristic", "abuse_feed_placeholder"])
    max_exposed_ports: int = 3


@dataclass(slots=True)
class ModeConfig:
    name: str = "normal"
    enabled_categories: List[str] = field(
        default_factory=lambda: [
            "network_privacy",
            "browser_privacy",
            "system_opsec",
            "fingerprinting",
            "behavioral",
            "reconnaissance",
            "environment",
        ]
    )
    severity_bias: Dict[str, int] = field(default_factory=lambda: {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0})
    scenario_confidence_floor: int = 40
    fingerprint_integrity_floor: int = 70
    external_recon_enabled: bool = True
    live_monitoring_enabled: bool = False


@dataclass(slots=True)
class AIConfig:
    enabled: bool = True
    api_key: Optional[str] = None
    model: str = "claude-opus-4-1"
    timeout_seconds: int = 45


@dataclass(slots=True)
class ReportConfig:
    title: str = "OPSEC Sentinel AI Report"
    dark_theme: bool = True


@dataclass(slots=True)
class AppConfig:
    engine: EngineConfig = field(default_factory=EngineConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    system: SystemConfig = field(default_factory=SystemConfig)
    fingerprint: FingerprintConfig = field(default_factory=FingerprintConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    behavioral: BehavioralConfig = field(default_factory=BehavioralConfig)
    recon: ReconConfig = field(default_factory=ReconConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    mode: ModeConfig = field(default_factory=ModeConfig)
    env_path: Optional[str] = None
