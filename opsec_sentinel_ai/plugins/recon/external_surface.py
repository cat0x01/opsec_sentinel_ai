from __future__ import annotations

from datetime import datetime, timezone

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin


class ExternalReconPlugin(ScannerPlugin):
    plugin_id = "recon.external_surface"
    name = "External Recon Surface Estimator"
    category = "reconnaissance"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        listeners = []
        previous = ctx.get_shared("raw_results", [])
        for result in previous:
            if result.get("plugin_id") == "system.open_ports":
                listeners = result.get("data", {}).get("listening_ports", [])
                break

        exposed = [item for item in listeners if item.get("ip") in {"0.0.0.0", "::"}]
        findings = []
        status = ScanStatus.ok
        if exposed and ctx.config.recon.enabled:
            status = ScanStatus.warning
            severity = Severity.high if len(exposed) > ctx.config.recon.max_exposed_ports else Severity.medium
            findings.append(
                Finding(
                    id="recon.public_attack_surface",
                    title="Externally reachable attack surface likely present",
                    severity=severity,
                    description="Services bound on wildcard interfaces increase the probability of host discovery, fingerprinting, and credential attack pressure.",
                    recommendation="Move administrative services to loopback or a dedicated VPN interface and validate perimeter filtering from an external vantage point.",
                    evidence={"exposed_listeners": exposed, "simulated_reputation": "unknown"},
                )
            )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"exposed_listeners": exposed},
            findings=findings,
            started_at=started_at,
        )
