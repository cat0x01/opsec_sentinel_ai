from __future__ import annotations

from datetime import datetime, timezone

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin
from opsec_sentinel_ai.utils.time import local_time_info


class TimezoneIpMismatchPlugin(ScannerPlugin):
    plugin_id = "fingerprint.timezone_ip"
    name = "Timezone vs IP Mismatch"
    category = "fingerprint_analysis"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        status = ScanStatus.ok
        findings = []

        local_info = local_time_info()
        geoip = None
        mismatch = None

        if ctx.config.fingerprint.geoip_url:
            try:
                response = await ctx.http.get(ctx.config.fingerprint.geoip_url, timeout=10)
                response.raise_for_status()
                geoip = response.json()
                geo_tz = str(geoip.get("timezone")) if geoip else None
                mismatch = geo_tz and geo_tz not in local_info.get("timezone_name", "")
            except Exception as exc:
                status = ScanStatus.warning
                findings.append(
                    Finding(
                        id="geoip.failed",
                        title="GeoIP lookup failed",
                        severity=Severity.low,
                        description=f"Unable to fetch GeoIP timezone data: {exc}",
                        recommendation="Provide a trusted GeoIP endpoint if timezone mismatch checks are required.",
                    )
                )

        if mismatch:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="timezone.mismatch",
                    title="Timezone and GeoIP mismatch",
                    severity=Severity.medium,
                    description="Local timezone does not align with GeoIP-reported timezone.",
                    recommendation="Align device timezone with network location or use privacy routing that matches timezone.",
                    evidence={"local_timezone": local_info, "geoip": geoip},
                )
            )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"local": local_info, "geoip": geoip, "mismatch": mismatch},
            findings=findings,
            started_at=started_at,
        )
