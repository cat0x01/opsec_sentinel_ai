from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Callable, Iterable, List, Optional

from opsec_sentinel_ai.core.collector import ResultCollector
from opsec_sentinel_ai.core.context import ScanContext
from opsec_sentinel_ai.core.models import ScanResult, ScanStatus
from opsec_sentinel_ai.core.plugin import ScannerPlugin


class ScanEngine:
    def __init__(
        self,
        ctx: ScanContext,
        plugins: Iterable[ScannerPlugin],
        on_start: Optional[Callable[[ScannerPlugin], None]] = None,
        on_complete: Optional[Callable[[ScannerPlugin, ScanResult], None]] = None,
    ) -> None:
        self.ctx = ctx
        self.plugins = list(plugins)
        self.collector = ResultCollector()
        self._sem = asyncio.Semaphore(ctx.config.engine.max_concurrency)
        self._on_start = on_start
        self._on_complete = on_complete

    async def run(self) -> List[ScanResult]:
        tasks = [asyncio.create_task(self._run_plugin(plugin)) for plugin in self.plugins]
        await asyncio.gather(*tasks)
        return self.collector.results()

    async def _run_plugin(self, plugin: ScannerPlugin) -> None:
        async with self._sem:
            start = datetime.now(timezone.utc).isoformat()
            if self._on_start:
                self._on_start(plugin)
            try:
                if plugin.resource_lock:
                    lock = await self.ctx.get_lock(plugin.resource_lock)
                    async with lock:
                        result = await self._run_with_timeout(plugin)
                else:
                    result = await self._run_with_timeout(plugin)
            except Exception as exc:  # pragma: no cover - defensive
                result = ScanResult(
                    plugin_id=plugin.plugin_id,
                    name=plugin.name,
                    category=plugin.category,
                    status=ScanStatus.error,
                    data={},
                    errors=[f"Unhandled exception: {exc}"],
                )
            end = datetime.now(timezone.utc).isoformat()
            result.started_at = result.started_at or start
            result.ended_at = result.ended_at or end
            await self.collector.add_result(result)
            self.ctx.set_shared("raw_results", [item.to_dict() for item in self.collector.results()])
            if self._on_complete:
                self._on_complete(plugin, result)

    async def _run_with_timeout(self, plugin: ScannerPlugin) -> ScanResult:
        if plugin.timeout_seconds:
            return await asyncio.wait_for(plugin.run(self.ctx), timeout=plugin.timeout_seconds)
        return await plugin.run(self.ctx)
