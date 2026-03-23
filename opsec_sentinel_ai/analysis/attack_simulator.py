from __future__ import annotations

from typing import Any, Dict, List


SCENARIO_DEFINITIONS = [
    {
        "id": "correlation.identity_collision",
        "name": "Identity Correlation Collision",
        "description": "Correlates IP geography, timezone, headers, and browser claims to estimate operator deanonymization likelihood.",
        "requires": {"fingerprint.timezone_ip_mismatch", "fingerprint.header_consistency"},
        "base_probability": 0.32,
        "weight": 1.3,
    },
    {
        "id": "browser.persistent_tracking",
        "name": "Persistent Browser Tracking",
        "description": "Models long-lived browser fingerprint linking across sessions using WebGL, canvas, fonts, and UA consistency gaps.",
        "requires": {"browser.webgl_fingerprint", "browser.canvas_entropy", "fingerprint.consistency"},
        "base_probability": 0.36,
        "weight": 1.4,
    },
    {
        "id": "network.dns_webrtc_exposure",
        "name": "Network Leak Chaining",
        "description": "Estimates whether an observer can bridge application traffic to origin infrastructure through DNS, WebRTC, IPv6, or clearnet leakage.",
        "requires": {"network.dns_leak", "browser.webrtc_leak", "network.ipv6_exposure"},
        "base_probability": 0.41,
        "weight": 1.6,
    },
    {
        "id": "traffic.timing_correlation",
        "name": "Traffic Timing Correlation",
        "description": "Assesses whether repetitive cadence, low jitter, or burst behavior makes sessions correlatable across entry and exit points.",
        "requires": {"behavioral.timing_anomaly"},
        "base_probability": 0.28,
        "weight": 1.2,
    },
]

SEVERITY_BONUS = {"critical": 0.22, "high": 0.16, "medium": 0.08, "low": 0.03, "info": 0.0}


def simulate_attack_paths(results: List[Dict[str, Any]], mode_name: str) -> Dict[str, Any]:
    indexed = {item.get("plugin_id"): item for item in results}
    scenarios: List[Dict[str, Any]] = []
    probabilities: List[float] = []

    for definition in SCENARIO_DEFINITIONS:
        matched = [indexed[plugin_id] for plugin_id in definition["requires"] if plugin_id in indexed]
        if not matched:
            continue

        severity_score = 0.0
        supporting_findings = []
        for result in matched:
            for finding in result.get("findings", []):
                severity = str(finding.get("severity", "info"))
                severity_score += SEVERITY_BONUS.get(severity, 0.0)
                supporting_findings.append(
                    {
                        "plugin_id": result.get("plugin_id"),
                        "finding_id": finding.get("id"),
                        "severity": severity,
                        "title": finding.get("title"),
                    }
                )

        confidence = min(0.97, definition["base_probability"] + (severity_score * definition["weight"]))
        risk_score = int(round(confidence * 100))
        probabilities.append(confidence)
        scenarios.append(
            {
                "scenario_id": definition["id"],
                "name": definition["name"],
                "description": definition["description"],
                "mode": mode_name,
                "success_probability": round(confidence, 2),
                "risk_score": risk_score,
                "supporting_findings": supporting_findings,
            }
        )

    overall_probability = max(probabilities, default=0.0)
    return {
        "mode": mode_name,
        "attack_surface_score": int(round(sum(probabilities) / max(len(probabilities), 1) * 100)),
        "max_attack_success_probability": round(overall_probability, 2),
        "scenarios": sorted(scenarios, key=lambda item: item["risk_score"], reverse=True),
    }
