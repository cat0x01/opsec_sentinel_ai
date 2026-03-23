from __future__ import annotations

from datetime import datetime, timezone

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin


class HeaderConsistencyPlugin(ScannerPlugin):
    plugin_id = "fingerprint.header_consistency"
    name = "Header Consistency"
    category = "fingerprint_analysis"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        status = ScanStatus.ok
        findings = []
        headers = None

        if ctx.config.fingerprint.header_check_url:
            try:
                response = await ctx.http.get(ctx.config.fingerprint.header_check_url, timeout=10)
                response.raise_for_status()
                headers = response.json().get("headers") if response.headers.get("content-type", "").startswith("application/json") else response.headers
            except Exception as exc:
                status = ScanStatus.warning
                findings.append(
                    Finding(
                        id="headers.failed",
                        title="Header consistency check failed",
                        severity=Severity.low,
                        description=f"Unable to fetch header echo: {exc}",
                        recommendation="Provide a trusted header echo endpoint.",
                    )
                )

        if headers:
            via = headers.get("Via") or headers.get("via")
            xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
            if via or xff:
                status = ScanStatus.warning
                findings.append(
                    Finding(
                        id="headers.forwarded",
                        title="Forwarded headers detected",
                        severity=Severity.low,
                        description="Forwarded headers indicate proxy or gateway traversal.",
                        recommendation="Ensure proxies are expected and avoid leaking real IPs.",
                        evidence={"via": via, "x_forwarded_for": xff},
                    )
                )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"headers": headers},
            findings=findings,
            started_at=started_at,
        )
