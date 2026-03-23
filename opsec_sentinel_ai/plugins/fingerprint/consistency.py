from __future__ import annotations

from datetime import datetime, timezone

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin


class FingerprintConsistencyPlugin(ScannerPlugin):
    plugin_id = "fingerprint.consistency"
    name = "Advanced Fingerprint Consistency"
    category = "fingerprinting"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        previous = ctx.get_shared("raw_results", [])
        findings = []
        anomalies = []

        for result in previous:
            if result.get("plugin_id") == "browser.webgl_fingerprint" and result.get("findings"):
                anomalies.append("webgl_gpu_surface")
            if result.get("plugin_id") == "fingerprint.timezone_ip_mismatch" and result.get("findings"):
                anomalies.append("timezone_ip_mismatch")
            if result.get("plugin_id") == "fingerprint.header_consistency" and result.get("findings"):
                anomalies.append("ua_header_mismatch")

        status = ScanStatus.ok
        if anomalies:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="fingerprint.ua_os_mismatch",
                    title="Browser fingerprint stack is internally inconsistent",
                    severity=Severity.high if "timezone_ip_mismatch" in anomalies else Severity.medium,
                    description="Multiple browser and network traits do not align cleanly, increasing linkability across sessions and vantage points.",
                    recommendation="Standardize browser profile, timezone, locale, and hardware exposure to a single believable operating environment.",
                    evidence={"anomalies": anomalies},
                )
            )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"anomalies": anomalies},
            findings=findings,
            started_at=started_at,
            metadata={"session_consistent": not anomalies},
        )
