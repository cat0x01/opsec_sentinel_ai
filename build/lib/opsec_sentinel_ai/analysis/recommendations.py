from __future__ import annotations

from typing import Any, Dict, List


RECOMMENDATION_MAP = {
    "dns.public.resolvers": {
        "summary": "Pin DNS to the anonymity transport instead of system-level public resolvers.",
        "commands": [
            "resolvectl status",
            "sudo resolvectl dns tun0 10.64.0.1",
            "sudo resolvectl domain tun0 '~.'",
        ],
        "paths": ["/etc/systemd/resolved.conf", "/etc/resolv.conf"],
    },
    "webrtc.ip_detected": {
        "summary": "Disable peer-to-peer address exposure in the browser profile used for sensitive workflows.",
        "commands": [
            "firefox -new-tab about:config",
            "Set media.peerconnection.enabled=false",
            "Set media.peerconnection.ice.default_address_only=true",
        ],
        "paths": ["Firefox profile prefs.js"],
    },
    "ports.listening": {
        "summary": "Constrain listeners to loopback or a dedicated enclave interface and drop unintended ingress.",
        "commands": [
            "sudo ss -tulpen",
            "sudo nft list ruleset",
            "sudo ufw deny <port>/tcp",
        ],
        "paths": ["/etc/nftables.conf", "/etc/ufw/user.rules"],
    },
    "fingerprint.ua_os_mismatch": {
        "summary": "Align browser headers, navigator properties, and platform claims with the actual host profile.",
        "commands": [
            "grep -n \"general.useragent.override\" ~/.mozilla/firefox/*/prefs.js",
            "grep -n \"privacy.resistFingerprinting\" ~/.mozilla/firefox/*/prefs.js",
        ],
        "paths": ["~/.mozilla/firefox/<profile>/prefs.js"],
    },
}


def build_recommendation_plan(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    plan: List[Dict[str, Any]] = []
    for result in results:
        for finding in result.get("findings", []):
            finding_id = str(finding.get("id", ""))
            if finding_id not in RECOMMENDATION_MAP:
                continue
            mapped = RECOMMENDATION_MAP[finding_id]
            plan.append(
                {
                    "finding_id": finding_id,
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "summary": mapped["summary"],
                    "commands": mapped["commands"],
                    "paths": mapped["paths"],
                }
            )
    return plan
