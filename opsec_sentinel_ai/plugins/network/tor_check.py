from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin
from opsec_sentinel_ai.utils.net import check_local_port, detect_proxy_env


class TorConnectivityPlugin(ScannerPlugin):
    plugin_id = "network.tor_connectivity"
    name = "Tor Connectivity & Exit Verification"
    category = "network_privacy"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        proxy_env = detect_proxy_env()
        tor_ports = [9050, 9150]
        open_ports = []

        status = ScanStatus.ok
        findings = []
        verification: Optional[Dict[str, str]] = None
        port_scan_error: Optional[str] = None

        for port in tor_ports:
            try:
                if check_local_port("127.0.0.1", port):
                    open_ports.append(port)
            except Exception as exc:
                port_scan_error = str(exc)

        if port_scan_error:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="tor.port.scan.failed",
                    title="Tor local port check partially failed",
                    severity=Severity.low,
                    description=f"Could not fully probe Tor local ports: {port_scan_error}",
                    recommendation="Run scan with sufficient local socket permissions or verify Tor manually with `ss -tulpen`.",
                )
            )

        if not open_ports and not proxy_env:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="tor.not_detected",
                    title="Tor proxy not detected",
                    severity=Severity.low,
                    description="No local Tor SOCKS port or proxy environment variables were detected.",
                    recommendation="If Tor is required, ensure the local Tor service is running and configure SOCKS proxy settings.",
                )
            )

        if ctx.config.network.tor_check_url:
            try:
                response = await ctx.http.get(ctx.config.network.tor_check_url, timeout=10)
                response.raise_for_status()
                verification = response.json()
            except Exception as exc:  # pragma: no cover - network dependent
                status = ScanStatus.warning
                findings.append(
                    Finding(
                        id="tor.verify.failed",
                        title="Tor exit verification failed",
                        severity=Severity.low,
                        description=f"Could not verify Tor exit status: {exc}",
                        recommendation="Verify Tor connectivity using a trusted check endpoint.",
                    )
                )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"proxy_env": proxy_env, "tor_ports_open": open_ports, "verification": verification},
            findings=findings,
            started_at=started_at,
        )
