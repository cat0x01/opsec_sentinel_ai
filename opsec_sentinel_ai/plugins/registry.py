from __future__ import annotations

from typing import List

from opsec_sentinel_ai.core.plugin import ScannerPlugin
from opsec_sentinel_ai.plugins.behavioral.timing_anomaly import TimingAnomalyPlugin
from opsec_sentinel_ai.plugins.browser.canvas_entropy import CanvasFingerprintPlugin
from opsec_sentinel_ai.plugins.browser.webrtc_leak import WebRTCLeakPlugin
from opsec_sentinel_ai.plugins.browser.webgl_fingerprint import WebGLFingerprintPlugin
from opsec_sentinel_ai.plugins.environment.sandbox_vm import SandboxVmDetectionPlugin
from opsec_sentinel_ai.plugins.fingerprint.consistency import FingerprintConsistencyPlugin
from opsec_sentinel_ai.plugins.fingerprint.entropy_score import FingerprintEntropyPlugin
from opsec_sentinel_ai.plugins.fingerprint.header_consistency import HeaderConsistencyPlugin
from opsec_sentinel_ai.plugins.fingerprint.timezone_ip import TimezoneIpMismatchPlugin
from opsec_sentinel_ai.plugins.network.dns_leak import DNSLeakPlugin
from opsec_sentinel_ai.plugins.network.ipv6_exposure import IPv6ExposurePlugin
from opsec_sentinel_ai.plugins.network.proxy_env import ProxyEnvironmentPlugin
from opsec_sentinel_ai.plugins.network.tor_check import TorConnectivityPlugin
from opsec_sentinel_ai.plugins.recon.external_surface import ExternalReconPlugin
from opsec_sentinel_ai.plugins.runtime import instantiate_plugins, load_plugin_types
from opsec_sentinel_ai.plugins.system.open_ports import OpenPortsPlugin
from opsec_sentinel_ai.plugins.system.ssh_audit import SSHAuditPlugin
from opsec_sentinel_ai.plugins.system.suspicious_processes import SuspiciousProcessPlugin


def core_plugin_types():
    return [
        DNSLeakPlugin,
        TorConnectivityPlugin,
        IPv6ExposurePlugin,
        ProxyEnvironmentPlugin,
        WebRTCLeakPlugin,
        WebGLFingerprintPlugin,
        CanvasFingerprintPlugin,
        OpenPortsPlugin,
        SuspiciousProcessPlugin,
        SSHAuditPlugin,
        TimezoneIpMismatchPlugin,
        HeaderConsistencyPlugin,
        FingerprintConsistencyPlugin,
        TimingAnomalyPlugin,
        SandboxVmDetectionPlugin,
        ExternalReconPlugin,
        FingerprintEntropyPlugin,
    ]


def all_plugins(plugin_dirs: List[str] | None = None) -> List[ScannerPlugin]:
    plugin_types = list(core_plugin_types())
    if plugin_dirs:
        plugin_types.extend(load_plugin_types(plugin_dirs))
    return instantiate_plugins(plugin_types)


def pre_entropy_plugins(plugin_dirs: List[str] | None = None) -> List[ScannerPlugin]:
    selected = [plugin_type for plugin_type in core_plugin_types() if plugin_type is not FingerprintEntropyPlugin]
    if plugin_dirs:
        selected.extend(load_plugin_types(plugin_dirs))
    return instantiate_plugins(selected)


def entropy_plugin() -> ScannerPlugin:
    return FingerprintEntropyPlugin()
