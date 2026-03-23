from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin


class SandboxVmDetectionPlugin(ScannerPlugin):
    plugin_id = "environment.sandbox_vm"
    name = "Sandbox / VM Detection"
    category = "environment"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        indicators = []
        paths = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/board_vendor",
        ]
        for raw_path in paths:
            path = Path(raw_path)
            if not path.exists():
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore").strip()
            except OSError:
                continue
            if any(marker in content.lower() for marker in ("virtualbox", "vmware", "qemu", "kvm", "hyper-v")):
                indicators.append({"path": raw_path, "value": content})

        findings = []
        status = ScanStatus.ok
        if indicators:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="environment.vm_detected",
                    title="Virtualization indicators detected",
                    severity=Severity.medium,
                    description="The host appears to expose virtualization metadata that can contribute to fingerprint uniqueness.",
                    recommendation="Harden the guest profile or isolate sensitive activity to a VM template with normalized hardware traits.",
                    evidence={"indicators": indicators},
                )
            )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"indicators": indicators},
            findings=findings,
            started_at=started_at,
        )
