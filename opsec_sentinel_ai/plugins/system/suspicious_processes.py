from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin


class SuspiciousProcessPlugin(ScannerPlugin):
    plugin_id = "system.suspicious_processes"
    name = "Suspicious Process Metadata"
    category = "system_opsec"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        status = ScanStatus.ok
        findings = []
        suspicious: List[dict] = []
        observed: List[dict] = []

        try:
            import psutil  # type: ignore

            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
                info = proc.info
                observed.append(info)
                exe = info.get("exe") or ""
                if any(indicator in exe for indicator in ctx.config.system.suspicious_path_indicators):
                    suspicious.append(info)
        except Exception as exc:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="process.scan.failed",
                    title="Process scan incomplete",
                    severity=Severity.low,
                    description=f"Process metadata scan failed: {exc}",
                    recommendation="Install psutil for deeper process inspection.",
                )
            )

        if suspicious:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="process.suspicious_paths",
                    title="Processes running from temporary locations",
                    severity=Severity.medium,
                    description="Processes appear to execute from temporary or user-writable locations.",
                    recommendation="Validate running processes and remove unknown executables.",
                    evidence={"processes": suspicious},
                )
            )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"observed_count": len(observed), "suspicious": suspicious},
            findings=findings,
            started_at=started_at,
        )
