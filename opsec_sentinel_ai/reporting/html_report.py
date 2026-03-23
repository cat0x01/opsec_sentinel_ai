from __future__ import annotations

from html import escape
from typing import Any, Dict, List

from opsec_sentinel_ai.reporting.scoring import compute_overall_risk_profile, compute_privacy_score, risk_summary


CYBERPUNK_CSS = """
:root {
  --bg: #0b0f14;
  --card: #111923;
  --accent: #00f5d4;
  --accent2: #ff2e97;
  --text: #e6f1ff;
  --muted: #93a4b8;
  --warning: #f0b429;
  --danger: #ff5c5c;
  --ok: #1dd3b0;
}
* { box-sizing: border-box; }
body { margin: 0; font-family: 'Share Tech Mono', 'JetBrains Mono', monospace; background: var(--bg); color: var(--text); }
header { padding: 32px; background: linear-gradient(120deg, #0f172a, #0b0f14 60%); border-bottom: 1px solid #1f2a3a; }
header h1 { margin: 0 0 8px; font-size: 28px; }
header .score { font-size: 20px; color: var(--accent); }
main { padding: 24px; display: grid; gap: 24px; }
.card { background: var(--card); border: 1px solid #1d2a3a; border-radius: 14px; padding: 20px; box-shadow: 0 0 24px rgba(0,245,212,0.08); }
.badge { display: inline-block; padding: 4px 8px; border-radius: 999px; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
.badge.low { background: rgba(240,180,41,0.2); color: var(--warning); }
.badge.medium { background: rgba(255,46,151,0.2); color: var(--accent2); }
.badge.high, .badge.critical { background: rgba(255,92,92,0.2); color: var(--danger); }
.badge.info { background: rgba(29,211,176,0.2); color: var(--ok); }
.section-title { margin: 0 0 12px; font-size: 18px; color: var(--accent); }
.finding { padding: 10px 0; border-bottom: 1px dashed #203042; }
.finding:last-child { border-bottom: none; }
.ai { white-space: pre-wrap; line-height: 1.6; color: var(--muted); }
.muted { color: var(--muted); }
.cmd { font-family: 'JetBrains Mono', monospace; font-size: 12px; background: #0c141f; border: 1px solid #203042; border-radius: 8px; padding: 6px 8px; margin-top: 6px; overflow-x: auto; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
.summary-item { padding: 10px; background: #0f1621; border-radius: 10px; text-align: center; }
.meter { height: 12px; background: #0f1621; border-radius: 999px; overflow: hidden; border: 1px solid #223245; }
.meter > span { display: block; height: 100%; background: linear-gradient(90deg, #ff2e97, #00f5d4); }
footer { padding: 16px 24px; color: var(--muted); font-size: 12px; }
@media (max-width: 640px) { header { padding: 20px; } main { padding: 16px; } }
"""


def render_html(
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
    findings = _flatten_findings(results)
    prioritized = _sort_findings_by_risk(findings)

    def render_findings() -> str:
        sections = []
        for result in results:
            items = []
            for finding in result.get("findings", []):
                sev = finding.get("severity", "info")
                commands = _recommended_commands(str(finding.get("id", "")), finding.get("evidence", {}))
                rendered_commands = "".join(f"<div class='cmd'>{escape(cmd)}</div>" for cmd in commands)
                items.append(
                    f"<div class='finding'><div class='badge {sev}'>{sev}</div>"
                    f"<div><strong>{escape(str(finding.get('title', 'Untitled finding')))}</strong></div>"
                    f"<div>{escape(str(finding.get('description', '')))}</div>"
                    f"<div><em>Recommendation:</em> {escape(str(finding.get('recommendation', '')))}</div>"
                    f"{rendered_commands}</div>"
                )
            sections.append(
                f"<div class='card'><div class='section-title'>{escape(str(result.get('name', 'Unnamed plugin')))}</div>"
                f"<div class='muted'>Status: {escape(str(result.get('status', 'unknown')))}</div>"
                f"{''.join(items) or '<div>No findings.</div>'}</div>"
            )
        return "".join(sections)

    def render_priority_plan() -> str:
        if not prioritized:
            return "<div class='card'><div class='section-title'>Priority Fix Plan</div><div>No actionable findings.</div></div>"

        lines = ["<div class='card'><div class='section-title'>Priority Fix Plan</div>"]
        for idx, finding in enumerate(prioritized[:5], start=1):
            commands = _recommended_commands(str(finding.get("id", "")), finding.get("evidence", {}))
            first_cmd = f"<div class='cmd'>{escape(commands[0])}</div>" if commands else ""
            lines.append(
                f"<div class='finding'><strong>{idx}. [{escape(str(finding.get('severity')))}] "
                f"{escape(str(finding.get('title')))}</strong>"
                f"<div class='muted'>{escape(str(finding.get('plugin_name')))}</div>"
                f"<div>{escape(str(finding.get('recommendation') or finding.get('description') or ''))}</div>"
                f"{first_cmd}</div>"
            )
        lines.append("</div>")
        return "".join(lines)

    return f"""
<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>{title}</title>
  <style>{CYBERPUNK_CSS}</style>
</head>
<body>
  <header>
    <h1>{escape(title)}</h1>
    <div class='muted'>Mode: {escape(mode_name)}</div>
    <div class='score'>Privacy Score: {score}/100</div>
    <div class='meter' aria-label='Privacy score meter'><span style='width:{score}%;'></span></div>
  </header>
  <main>
    <div class='card'>
      <div class='section-title'>Risk Summary</div>
      <div class='summary-grid'>
        <div class='summary-item'>Composite<br>{profile['composite_score']}</div>
        <div class='summary-item'>Critical<br>{summary['critical']}</div>
        <div class='summary-item'>High<br>{summary['high']}</div>
        <div class='summary-item'>Medium<br>{summary['medium']}</div>
        <div class='summary-item'>Low<br>{summary['low']}</div>
        <div class='summary-item'>Info<br>{summary['info']}</div>
      </div>
    </div>
    <div class='card'>
      <div class='section-title'>Attack Simulation</div>
      <div>Attack Surface Score: {(attack_paths or {}).get('attack_surface_score', 0)}/100</div>
      <div>Max Success Probability: {int(float((attack_paths or {}).get('max_attack_success_probability', 0.0)) * 100)}%</div>
      <div>Fingerprint Integrity: {(fingerprint_integrity or {}).get('integrity_score', 0)}/100</div>
      <div>Behavioral Assessment: {escape(str((behavioral or {}).get('assessment', 'unknown')))}</div>
    </div>
    {render_priority_plan()}
    <div class='card'>
      <div class='section-title'>Recommendations</div>
      {"".join(f"<div class='finding'><strong>{escape(str(item.get('title', 'Untitled')))}</strong><div>{escape(str(item.get('summary', '')))}</div><div class='cmd'>{escape(str(item.get('commands', [''])[0]))}</div></div>" for item in (recommendations or [])[:6]) or "<div>No mapped remediation steps.</div>"}
    </div>
    <div class='card'>
      <div class='section-title'>Visualization Payload</div>
      <div>Nodes: {len((visualization or {}).get('nodes', []))}</div>
      <div>Edges: {len((visualization or {}).get('edges', []))}</div>
      <div>Heatmap Cells: {len((visualization or {}).get('heatmap', []))}</div>
    </div>
    <div class='card'>
      <div class='section-title'>AI Analysis</div>
      <div class='ai'>{escape(ai_text or 'AI analysis not available.')}</div>
    </div>
    {render_findings()}
  </main>
  <footer>Generated by OPSEC Sentinel AI - defensive privacy auditing only.</footer>
</body>
</html>
"""


def _flatten_findings(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    flattened: List[Dict[str, Any]] = []
    for result in results:
        for finding in result.get("findings", []):
            flattened.append(
                {
                    "plugin_name": result.get("name", "Unknown plugin"),
                    "id": finding.get("id", ""),
                    "title": finding.get("title", ""),
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
