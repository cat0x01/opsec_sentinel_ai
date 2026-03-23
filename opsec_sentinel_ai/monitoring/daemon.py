from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List

from opsec_sentinel_ai.utils.net import is_private_ip, resolve_nameservers


class MonitoringDaemon:
    def __init__(self, cfg, logger) -> None:
        self.cfg = cfg
        self.logger = logger

    async def snapshot(self) -> Dict[str, Any]:
        nameservers = resolve_nameservers()
        alerts: List[Dict[str, Any]] = []
        if self.cfg.monitoring.alert_on_non_private_dns:
            public_resolvers = [ip for ip in nameservers if not is_private_ip(ip)]
            if public_resolvers:
                alerts.append(
                    {
                        "severity": "high" if self.cfg.mode.name == "darknet" else "medium",
                        "type": "dns_leak",
                        "message": "Public resolvers observed during monitoring window.",
                        "context": {"public_resolvers": public_resolvers},
                    }
                )

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nameservers": nameservers,
            "alerts": alerts,
        }

    async def run_once(self) -> Dict[str, Any]:
        snapshot = await self.snapshot()
        for alert in snapshot["alerts"]:
            self.logger.warning("monitor alert=%s severity=%s", alert["type"], alert["severity"])
        return snapshot

    async def stream(self, iterations: int = 3) -> List[Dict[str, Any]]:
        history = []
        for _ in range(iterations):
            history.append(await self.run_once())
            await asyncio.sleep(self.cfg.monitoring.interval_seconds)
        return history
