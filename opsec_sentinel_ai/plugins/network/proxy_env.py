from __future__ import annotations

from datetime import datetime, timezone

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin
from opsec_sentinel_ai.utils.net import detect_proxy_env


class ProxyEnvironmentPlugin(ScannerPlugin):
    plugin_id = "network.proxy_env"
    name = "Proxy Environment Leak Check"
    category = "network_privacy"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        proxies = detect_proxy_env()
        findings = []
        status = ScanStatus.ok

        if not proxies and ctx.config.network.proxy_required:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="proxy.missing",
                    title="Proxy not configured",
                    severity=Severity.medium,
                    description="Policy indicates a proxy is required, but none were detected.",
                    recommendation="Configure required proxy environment variables or system proxy settings.",
                )
            )

        if proxies:
            findings.append(
                Finding(
                    id="proxy.detected",
                    title="Proxy environment variables detected",
                    severity=Severity.info,
                    description="Proxy variables were found in the environment.",
                    recommendation="Ensure proxy endpoints are trusted and avoid leaks outside the proxy.",
                    evidence={"proxy_env": proxies},
                )
            )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"proxy_env": proxies},
            findings=findings,
            started_at=started_at,
        )
