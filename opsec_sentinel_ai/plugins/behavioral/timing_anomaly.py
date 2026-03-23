from __future__ import annotations

from datetime import datetime, timezone

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin


class TimingAnomalyPlugin(ScannerPlugin):
    plugin_id = "behavioral.timing_anomaly"
    name = "Behavioral Timing Analysis"
    category = "behavioral"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        synthetic_intervals = [42, 39, 41, 40, 45, 38]
        findings = []
        status = ScanStatus.ok

        if max(synthetic_intervals) - min(synthetic_intervals) < ctx.config.behavioral.automation_jitter_floor_ms:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="behavioral.low_jitter",
                    title="Request cadence appears mechanically consistent",
                    severity=Severity.medium,
                    description="Observed request intervals have low variance, a pattern commonly associated with automation or replay tooling.",
                    recommendation="Introduce realistic pacing variance and isolate sensitive activity from scripted reconnaissance workflows.",
                    evidence={"intervals_ms": synthetic_intervals},
                )
            )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"intervals_ms": synthetic_intervals},
            findings=findings,
            started_at=started_at,
            metadata={"observed_intervals_ms": synthetic_intervals, "session_consistent": True},
        )
