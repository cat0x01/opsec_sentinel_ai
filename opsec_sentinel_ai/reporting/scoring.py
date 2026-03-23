from __future__ import annotations

from typing import Dict, List

from opsec_sentinel_ai.core.models import Severity


SEVERITY_WEIGHTS = {
    Severity.critical.value: 25,
    Severity.high.value: 15,
    Severity.medium.value: 8,
    Severity.low.value: 3,
    Severity.info.value: 0,
}


def compute_privacy_score(results: List[Dict], weights: Dict[str, int] | None = None) -> int:
    active_weights = weights or SEVERITY_WEIGHTS
    score = 100
    for result in results:
        for finding in result.get("findings", []):
            score -= active_weights.get(finding.get("severity", ""), 0)
    return max(0, min(100, score))


def risk_summary(results: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for result in results:
        for finding in result.get("findings", []):
            severity = finding.get("severity")
            if severity in counts:
                counts[severity] += 1
    return counts


def compute_overall_risk_profile(
    results: List[Dict],
    attack_paths: Dict | None = None,
    fingerprint_integrity: Dict | None = None,
    weights: Dict[str, int] | None = None,
) -> Dict[str, int | str]:
    summary = risk_summary(results)
    score = compute_privacy_score(results, weights=weights)
    attack_score = int((attack_paths or {}).get("attack_surface_score", 0))
    fingerprint_score = int((fingerprint_integrity or {}).get("integrity_score", 100))
    composite = max(0, min(100, round((score * 0.45) + (fingerprint_score * 0.25) + ((100 - attack_score) * 0.30))))
    return {
        "privacy_score": score,
        "attack_surface_score": attack_score,
        "fingerprint_integrity_score": fingerprint_score,
        "composite_score": composite,
        "critical_findings": summary["critical"],
        "high_findings": summary["high"],
    }
