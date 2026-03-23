from __future__ import annotations

from datetime import datetime, timezone

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin
from opsec_sentinel_ai.utils.net import is_private_ip, resolve_nameservers


class DNSLeakPlugin(ScannerPlugin):
    plugin_id = "network.dns_leak"
    name = "DNS Leak Detection"
    category = "network_privacy"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        nameservers = resolve_nameservers()
        findings = []
        status = ScanStatus.ok

        if not nameservers:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="dns.nameserver.missing",
                    title="No DNS nameservers detected",
                    severity=Severity.medium,
                    description="Unable to determine system DNS resolvers; audit coverage is limited.",
                    recommendation="Verify DNS configuration manually and ensure resolvers are trusted.",
                )
            )
        else:
            public_servers = [ip for ip in nameservers if not is_private_ip(ip)]
            if public_servers:
                status = ScanStatus.warning
                findings.append(
                    Finding(
                        id="dns.public.resolvers",
                        title="Public DNS resolvers detected",
                        severity=Severity.low,
                        description="System is configured to use public resolvers which may reveal queries to third parties.",
                        recommendation="Use a trusted resolver or tunnel DNS through a privacy-preserving service.",
                        evidence={"public_resolvers": public_servers},
                    )
                )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"nameservers": nameservers},
            findings=findings,
            started_at=started_at,
        )
