from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin
from opsec_sentinel_ai.utils.entropy import shannon_entropy


class FingerprintEntropyPlugin(ScannerPlugin):
    plugin_id = "fingerprint.entropy_score"
    name = "Fingerprint Entropy Scoring"
    category = "fingerprint_analysis"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        status = ScanStatus.ok
        findings: List[Finding] = []

        components = _collect_components(ctx.get_shared("raw_results", []))
        combined = "|".join(f"{k}:{v}" for k, v in components.items())
        entropy = shannon_entropy(combined)

        if entropy > 4.5:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="fingerprint.high_entropy",
                    title="High fingerprint entropy",
                    severity=Severity.low,
                    description="Collected attributes provide a moderately unique fingerprint.",
                    recommendation="Reduce exposed browser/system attributes where possible.",
                    evidence={"entropy": entropy, "components": components},
                )
            )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"entropy": entropy, "components": components},
            findings=findings,
            started_at=started_at,
        )


def _collect_components(results: List[Dict]) -> Dict[str, str]:
    components: Dict[str, str] = {}
    for result in results:
        plugin_id = result.get("plugin_id", "")
        data = result.get("data", {})
        if plugin_id == "browser.webgl_fingerprint":
            components["webgl_vendor"] = str(data.get("unmasked_vendor") or data.get("vendor") or "")
            components["webgl_renderer"] = str(data.get("unmasked_renderer") or data.get("renderer") or "")
        if plugin_id == "browser.canvas_entropy":
            components["canvas_entropy"] = str(data.get("entropy"))
        if plugin_id == "browser.webrtc_leak":
            components["webrtc_candidates"] = str(len(data.get("candidates") or []))
        if plugin_id == "fingerprint.timezone_ip":
            components["timezone"] = str(data.get("local", {}).get("timezone_name"))
        if plugin_id == "network.ipv6_exposure":
            components["ipv6_count"] = str(len(data.get("ipv6_addresses") or []))
    return components
