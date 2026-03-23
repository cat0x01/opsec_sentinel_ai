from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ScanStatus(str, Enum):
    ok = "ok"
    warning = "warning"
    error = "error"
    skipped = "skipped"


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class ScanResult:
    plugin_id: str
    name: str
    category: str
    status: ScanStatus
    data: Dict[str, Any]
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[str] = None
    ended_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "category": self.category,
            "status": self.status.value,
            "data": self.data,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
            "metadata": self.metadata,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }
