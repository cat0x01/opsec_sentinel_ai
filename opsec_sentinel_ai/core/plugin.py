from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from opsec_sentinel_ai.core.context import ScanContext
from opsec_sentinel_ai.core.models import ScanResult


class ScannerPlugin(ABC):
    plugin_id: str = "base"
    name: str = "Base"
    category: str = "base"
    resource_lock: Optional[str] = None
    timeout_seconds: Optional[int] = None

    @abstractmethod
    async def run(self, ctx: ScanContext) -> ScanResult:
        raise NotImplementedError
