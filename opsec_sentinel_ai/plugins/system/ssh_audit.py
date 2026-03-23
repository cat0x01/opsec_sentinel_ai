from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin


class SSHAuditPlugin(ScannerPlugin):
    plugin_id = "system.ssh_audit"
    name = "SSH Configuration Audit"
    category = "system_opsec"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        findings = []
        status = ScanStatus.ok

        configs: Dict[str, Dict[str, str]] = {}
        paths = [Path("/etc/ssh/sshd_config"), Path.home() / ".ssh" / "config"]

        for path in paths:
            if not path.exists():
                continue
            try:
                configs[str(path)] = _parse_ssh_config(path)
            except Exception as exc:
                status = ScanStatus.warning
                findings.append(
                    Finding(
                        id="ssh.read.failed",
                        title="SSH config read failed",
                        severity=Severity.low,
                        description=f"Could not read {path}: {exc}",
                        recommendation="Verify permissions for SSH configuration files.",
                    )
                )

        sshd = configs.get("/etc/ssh/sshd_config", {})
        if sshd:
            if sshd.get("PermitRootLogin", "yes").lower() not in {"no", "prohibit-password"}:
                status = ScanStatus.warning
                findings.append(
                    Finding(
                        id="ssh.root.login",
                        title="PermitRootLogin is enabled",
                        severity=Severity.medium,
                        description="Root login via SSH can increase attack surface.",
                        recommendation="Set PermitRootLogin to 'no' or 'prohibit-password'.",
                        evidence={"PermitRootLogin": sshd.get("PermitRootLogin", "yes")},
                    )
                )
            if sshd.get("PasswordAuthentication", "yes").lower() == "yes":
                status = ScanStatus.warning
                findings.append(
                    Finding(
                        id="ssh.password.auth",
                        title="PasswordAuthentication enabled",
                        severity=Severity.medium,
                        description="Password authentication is enabled for SSH.",
                        recommendation="Disable password authentication and use key-based auth only.",
                        evidence={"PasswordAuthentication": sshd.get("PasswordAuthentication", "yes")},
                    )
                )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data={"configs": configs},
            findings=findings,
            started_at=started_at,
        )


def _parse_ssh_config(path: Path) -> Dict[str, str]:
    settings: Dict[str, str] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if " " in line:
                key, value = line.split(None, 1)
                settings[key] = value
    return settings
