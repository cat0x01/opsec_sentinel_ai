from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin
from opsec_sentinel_ai.utils.net import check_local_port


class OpenPortsPlugin(ScannerPlugin):
    plugin_id = "system.open_ports"
    name = "Open Local Ports Check"
    category = "system_opsec"

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        status = ScanStatus.ok
        findings = []

        open_ports: List[int] = []
        psutil_ports: List[dict] = []

        try:
            import psutil  # type: ignore

            for conn in psutil.net_connections(kind="inet"):
                if conn.status != psutil.CONN_LISTEN:
                    continue
                laddr = conn.laddr
                if not laddr:
                    continue
                ip = laddr.ip
                port = laddr.port
                if ip in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
                    psutil_ports.append({"ip": ip, "port": port, "pid": conn.pid})
        except Exception:
            for port in ctx.config.system.open_ports_common:
                if check_local_port("127.0.0.1", port):
                    open_ports.append(port)

        if psutil_ports:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="ports.listening",
                    title="Listening local ports detected",
                    severity=Severity.medium,
                    description="Local services are listening on common interfaces.",
                    recommendation="Review exposed services and limit listeners to trusted addresses.",
                    evidence={"listening": psutil_ports},
                )
            )
        elif open_ports:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="ports.common",
                    title="Common ports responding on localhost",
                    severity=Severity.low,
                    description="Common ports responded on localhost; verify necessity of services.",
                    recommendation="Disable or firewall unnecessary services.",
                    evidence={"open_ports": open_ports},
                )
            )

        data = {"listening_ports": psutil_ports, "open_ports": open_ports}
        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data=data,
            findings=findings,
            started_at=started_at,
        )
