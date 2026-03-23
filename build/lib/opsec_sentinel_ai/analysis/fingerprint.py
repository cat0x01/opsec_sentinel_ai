from __future__ import annotations

from typing import Any, Dict, List


def compute_fingerprint_integrity(results: List[Dict[str, Any]], floor: int) -> Dict[str, Any]:
    penalties = 0
    anomalies: List[Dict[str, Any]] = []
    watched = {
        "fingerprint.ua_os_mismatch": 16,
        "fingerprint.webgl_gpu_mismatch": 18,
        "fingerprint.fonts_resolution_anomaly": 12,
        "fingerprint.timezone_ip_mismatch": 14,
        "fingerprint.header.user_agent_mismatch": 15,
        "webrtc.ip_detected": 10,
        "webgl.exposed": 8,
    }

    for result in results:
        for finding in result.get("findings", []):
            finding_id = str(finding.get("id", ""))
            if finding_id in watched:
                penalties += watched[finding_id]
                anomalies.append(
                    {
                        "id": finding_id,
                        "title": finding.get("title"),
                        "severity": finding.get("severity"),
                    }
                )

    score = max(0, 100 - penalties)
    return {
        "integrity_score": score,
        "target_floor": floor,
        "status": "coherent" if score >= floor else "inconsistent",
        "anomalies": anomalies,
    }
