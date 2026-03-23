from opsec_sentinel_ai.analysis.attack_simulator import simulate_attack_paths
from opsec_sentinel_ai.analysis.fingerprint import compute_fingerprint_integrity
from opsec_sentinel_ai.reporting.scoring import compute_overall_risk_profile


def test_attack_simulation_and_composite_profile() -> None:
    results = [
        {
            "plugin_id": "network.dns_leak",
            "findings": [{"id": "dns.public.resolvers", "severity": "medium", "title": "Public DNS"}],
        },
        {
            "plugin_id": "browser.webrtc_leak",
            "findings": [{"id": "webrtc.ip_detected", "severity": "high", "title": "WebRTC leak"}],
        },
        {
            "plugin_id": "network.ipv6_exposure",
            "findings": [{"id": "ipv6.exposed", "severity": "medium", "title": "IPv6 exposure"}],
        },
        {
            "plugin_id": "fingerprint.consistency",
            "findings": [{"id": "fingerprint.ua_os_mismatch", "severity": "high", "title": "UA mismatch"}],
        },
    ]

    attack_paths = simulate_attack_paths(results, "darknet")
    integrity = compute_fingerprint_integrity(results, 85)
    profile = compute_overall_risk_profile(results, attack_paths=attack_paths, fingerprint_integrity=integrity)

    assert attack_paths["scenarios"]
    assert integrity["status"] == "inconsistent"
    assert profile["composite_score"] < 100
