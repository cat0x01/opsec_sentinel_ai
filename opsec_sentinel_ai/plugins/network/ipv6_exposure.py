from __future__ import annotations

from datetime import datetime, timezone

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin
from opsec_sentinel_ai.utils.net import get_ipv6_addresses, is_global_ip


class IPv6ExposurePlugin(ScannerPlugin):
    plugin_id = "network.ipv6_exposure"
    name = "IPv6 Exposure"
    category = "network_privacy"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        addresses = get_ipv6_addresses()
        global_addresses = [ip for ip in addresses if is_global_ip(ip)]

        status = ScanStatus.ok
        findings = []
        if global_addresses:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="ipv6.global",
                    title="Global IPv6 addresses detected",
                    severity=Severity.low,
                    description="Global IPv6 addresses can reveal network identity if not properly protected.",
                    recommendation="Consider disabling IPv6 or routing through privacy-preserving networks if required.",
                    evidence={"global_ipv6": global_addresses},
                )
            )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"ipv6_addresses": addresses},
            findings=findings,
            started_at=started_at,
        )
