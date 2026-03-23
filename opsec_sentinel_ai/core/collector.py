from __future__ import annotations

import asyncio
import json
from typing import Dict, List

from opsec_sentinel_ai.core.models import ScanResult


class ResultCollector:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._results: List[ScanResult] = []

    async def add_result(self, result: ScanResult) -> None:
        async with self._lock:
            self._results.append(result)

    async def extend(self, results: List[ScanResult]) -> None:
        async with self._lock:
            self._results.extend(results)

    def to_dict(self) -> Dict[str, List[Dict]]:
        return {"results": [r.to_dict() for r in self._results]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def results(self) -> List[ScanResult]:
        return list(self._results)
