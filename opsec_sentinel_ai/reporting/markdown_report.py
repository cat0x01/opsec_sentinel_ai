from __future__ import annotations

from typing import Any, Dict, List

from opsec_sentinel_ai.reporting.scoring import compute_overall_risk_profile, compute_privacy_score, risk_summary


def render_markdown(
    results: List[Dict[str, Any]],
    ai_text: str,
    title: str,
    *,
    attack_paths: Dict[str, Any] | None = None,
    behavioral: Dict[str, Any] | None = None,
    fingerprint_integrity: Dict[str, Any] | None = None,
    recommendations: List[Dict[str, Any]] | None = None,
    visualization: Dict[str, Any] | None = None,
    mode_name: str = "normal",
    score_weights: Dict[str, int] | None = None,
) -> str:
    score = compute_privacy_score(results, weights=score_weights)
    summary = risk_summary(results)
    profile = compute_overall_risk_profile(
        results,
        attack_paths=attack_paths,
        fingerprint_integrity=fingerprint_integrity,
        weights=score_weights,
    )
    meter = _render_meter(score)
    all_findings = _flatten_findings(results)
    prioritized = _sort_findings_by_risk(all_findings)

    lines = [
        f"# {title}",
        "",
        "## Executive Snapshot",
        f"**Mode:** {mode_name}",
        f"**Privacy Score:** {score}/100",
        f"**Composite Score:** {profile['composite_score']}/100",
        meter,
        "",
        "**Risk Summary:**",
        f"- Critical: {summary['critical']}",
        f"- High: {summary['high']}",
        f"- Medium: {summary['medium']}",
        f"- Low: {summary['low']}",
        f"- Info: {summary['info']}",
        "",
    ]

    if attack_paths:
        lines.extend(
            [
                "## Attack Simulation",
                f"- Attack Surface Score: {attack_paths.get('attack_surface_score', 0)}/100",
                f"- Maximum Success Probability: {int(float(attack_paths.get('max_attack_success_probability', 0.0)) * 100)}%",
            ]
        )
        for scenario in attack_paths.get("scenarios", [])[:5]:
            lines.append(
                f"- {scenario.get('name')}: {scenario.get('risk_score')}/100 risk, {int(float(scenario.get('success_probability', 0)) * 100)}% success probability"
            )
        lines.append("")

    if fingerprint_integrity:
        lines.extend(
            [
                "## Fingerprint Integrity",
                f"- Integrity Score: {fingerprint_integrity.get('integrity_score', 0)}/100",
                f"- Status: {fingerprint_integrity.get('status', 'unknown')}",
                "",
            ]
        )

    if behavioral:
        lines.extend(
            [
                "## Behavioral Analysis",
                f"- Assessment: {behavioral.get('assessment', 'unknown')}",
                f"- Automation Probability: {int(float(behavioral.get('automation_probability', 0)) * 100)}%",
                f"- Mean Interval: {behavioral.get('mean_interval_ms')}",
                f"- Jitter: {behavioral.get('jitter_ms')}",
                "",
            ]
        )

    lines.extend(_priority_fix_plan(prioritized))

    if recommendations:
        lines.append("## Technical Remediation")
        for item in recommendations[:6]:
            lines.append(f"- **{item.get('title')}** [{item.get('severity')}]")
            lines.append(f"  Summary: {item.get('summary')}")
            if item.get("commands"):
                lines.append(f"  Command: `{item['commands'][0]}`")
            if item.get("paths"):
                lines.append(f"  Path: `{item['paths'][0]}`")
        lines.append("")

    if visualization:
        lines.extend(
            [
                "## Visualization Data",
                f"- Graph Nodes: {len(visualization.get('nodes', []))}",
                f"- Graph Edges: {len(visualization.get('edges', []))}",
                f"- Heatmap Cells: {len(visualization.get('heatmap', []))}",
                "",
            ]
        )

    lines.extend([
        "## AI Analysis",
        ai_text or "AI analysis not available.",
        "",
        "## Findings",
    ])

    for result in results:
        lines.append(f"### {result.get('name')} ({result.get('category')})")
        lines.append(f"Status: {result.get('status')}")
        for finding in result.get("findings", []):
            lines.append(f"- **{finding.get('title')}** [{finding.get('severity')}] - {finding.get('description')}")
            recommendation = finding.get("recommendation")
            if recommendation:
                lines.append(f"- Recommendation: {recommendation}")
            commands = _recommended_commands(finding.get("id", ""), finding.get("evidence", {}))
            if commands:
                lines.append("- Suggested commands:")
                for cmd in commands:
                    lines.append(f"  - `{cmd}`")
        lines.append("")

    return "\n".join(lines)


def _render_meter(score: int) -> str:
    filled = int(score / 10)
    bar = "=" * filled + "-" * (10 - filled)
    return f"`{bar}`"


def _flatten_findings(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    flattened: List[Dict[str, Any]] = []
    for result in results:
        for finding in result.get("findings", []):
            flattened.append(
                {
                    "plugin_name": result.get("name", "Unknown plugin"),
                    "plugin_id": result.get("plugin_id", ""),
                    "category": result.get("category", "unknown"),
                    "id": finding.get("id", ""),
                    "title": finding.get("title", "Untitled finding"),
                    "severity": finding.get("severity", "info"),
                    "description": finding.get("description", ""),
                    "recommendation": finding.get("recommendation", ""),
                    "evidence": finding.get("evidence", {}),
                }
            )
    return flattened


def _sort_findings_by_risk(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    weights = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return sorted(findings, key=lambda f: weights.get(str(f.get("severity")), 0), reverse=True)


def _priority_fix_plan(findings: List[Dict[str, Any]]) -> List[str]:
    lines = ["## Priority Fix Plan"]
    if not findings:
        lines.append("No actionable findings were detected in this scan.")
        lines.append("")
        return lines

    top_findings = findings[:5]
    for index, finding in enumerate(top_findings, start=1):
        lines.append(f"{index}. [{finding.get('severity')}] {finding.get('title')} ({finding.get('plugin_name')})")
        recommendation = finding.get("recommendation")
        if recommendation:
            lines.append(f"   - Action: {recommendation}")
        commands = _recommended_commands(str(finding.get("id", "")), finding.get("evidence", {}))
        if commands:
            lines.append(f"   - Run: `{commands[0]}`")
    lines.append("")
    return lines


def _recommended_commands(finding_id: str, evidence: Dict[str, Any]) -> List[str]:
    if finding_id == "ports.listening":
        listening = evidence.get("listening", []) if isinstance(evidence, dict) else []
        exposed_ports = sorted(
            {
                item.get("port")
                for item in listening
                if isinstance(item, dict) and item.get("ip") in {"0.0.0.0", "::"} and item.get("port")
            }
        )
        deny_rules = " && ".join(f"sudo ufw deny {port}/tcp" for port in exposed_ports)
        return [
            "sudo ss -tulpen",
            "sudo lsof -i -P -n | grep LISTEN",
            "sudo ufw status verbose",
            deny_rules or "sudo ufw deny <port>/tcp",
        ]
    if finding_id == "ssh.root.login":
        return [
            "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak",
            "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config",
            "sudo sshd -t && sudo systemctl reload ssh || sudo systemctl reload sshd",
        ]
    if finding_id == "ssh.password.auth":
        return [
            "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
            "sudo sshd -t && sudo systemctl reload ssh || sudo systemctl reload sshd",
        ]
    if finding_id == "webrtc.ip_detected":
        return [
            "firefox -new-tab about:config",
            "Set media.peerconnection.enabled=false in Firefox about:config",
        ]
    if finding_id == "webgl.exposed":
        return [
            "firefox -new-tab about:config",
            "Set webgl.disabled=true and privacy.resistFingerprinting=true",
        ]
    if finding_id == "fingerprint.high_entropy":
        return [
            "firefox -new-tab about:config",
            "Set privacy.resistFingerprinting=true",
            "Set webgl.disabled=true and media.peerconnection.enabled=false",
        ]
    return []
