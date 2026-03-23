from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import httpx

from opsec_sentinel_ai.config.settings import AppConfig


@dataclass(slots=True)
class ScanContext:
    config: AppConfig
    logger: Any
    http: httpx.AsyncClient
    started_at: str
    shared: Dict[str, Any] = field(default_factory=dict)
    locks: Dict[str, asyncio.Lock] = field(default_factory=dict)

    async def get_lock(self, name: str) -> asyncio.Lock:
        if name not in self.locks:
            self.locks[name] = asyncio.Lock()
        return self.locks[name]

    def get_shared(self, key: str, default: Optional[Any] = None) -> Any:
        return self.shared.get(key, default)

    def set_shared(self, key: str, value: Any) -> None:
        self.shared[key] = value
