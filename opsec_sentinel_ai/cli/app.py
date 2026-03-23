from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from opsec_sentinel_ai.ai.analyzer import ClaudeAnalyzer
from opsec_sentinel_ai.analysis.attack_simulator import simulate_attack_paths
from opsec_sentinel_ai.analysis.behavioral import analyze_behavioral_patterns
from opsec_sentinel_ai.analysis.fingerprint import compute_fingerprint_integrity
from opsec_sentinel_ai.analysis.recommendations import build_recommendation_plan
from opsec_sentinel_ai.analysis.visualization import build_visualization_payload
from opsec_sentinel_ai.config.loader import load_config
from opsec_sentinel_ai.core.context import ScanContext
from opsec_sentinel_ai.core.engine import ScanEngine
from opsec_sentinel_ai.monitoring.daemon import MonitoringDaemon
from opsec_sentinel_ai.plugins.registry import entropy_plugin, pre_entropy_plugins
from opsec_sentinel_ai.reporting.html_report import render_html
from opsec_sentinel_ai.reporting.markdown_report import render_markdown
from opsec_sentinel_ai.reporting.scoring import compute_overall_risk_profile, compute_privacy_score, risk_summary
from opsec_sentinel_ai.reporting.pdf_export import export_pdf
from opsec_sentinel_ai.utils.logging import setup_logger


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OPSEC Sentinel AI - adversary simulation and anonymity auditing")
    parser.add_argument("--out-dir", default="./reports", help="Output directory for reports")
    parser.add_argument("--dotenv", default=None, help="Optional .env path")
    parser.add_argument("--mode", choices=["normal", "bugbounty", "darknet"], default="normal", help="Operational profile")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    parser.add_argument("--no-browser", action="store_true", help="Disable browser privacy checks")
    parser.add_argument("--monitor", action="store_true", help="Run one live monitoring snapshot after the scan")
    parser.add_argument("--list-plugins", action="store_true", help="List loaded plugins and exit")
    parser.add_argument("--debug-env", action="store_true", help="Show env loading diagnostics")
    parser.add_argument("--test-ai", action="store_true", help="Send a minimal AI request and exit")
    parser.add_argument("--test-ai-message", default="Why is fast inference important?", help="Test prompt for AI")
    parser.add_argument("--json", action="store_true", help="Write JSON scan output")
    parser.add_argument("--md", action="store_true", help="Write Markdown report")
    parser.add_argument("--html", action="store_true", help="Write HTML report")
    parser.add_argument("--pdf", action="store_true", help="Write PDF report (requires weasyprint)")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    asyncio.run(run(args))


async def run(args: argparse.Namespace) -> None:
    console = Console()
    logger = setup_logger()
    cfg = load_config(args.dotenv, mode_name=args.mode)

    if args.no_ai:
        cfg.ai.enabled = False
    if args.no_browser:
        cfg.browser.enabled = False

    if args.debug_env:
        _print_env_debug(console, cfg)

    plugins = pre_entropy_plugins(cfg.engine.plugin_directories)
    if args.list_plugins:
        _print_plugin_inventory(console, plugins, cfg.mode.name)
        return

    if args.test_ai:
        analyzer = ClaudeAnalyzer(cfg.ai, logger)
        result = await analyzer.test_request(args.test_ai_message)
        console.print(result.raw, markup=False)
        return

    if cfg.ai.enabled and not cfg.ai.api_key:
        console.print(
            "[yellow]AI analysis is enabled but no ANTHROPIC_API_KEY was found. "
            "Create a .env file or export the environment variable.[/]"
        )

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    async with httpx.AsyncClient() as http_client:
        ctx = ScanContext(
            config=cfg,
            logger=logger,
            http=http_client,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        if not cfg.browser.enabled:
            plugins = [p for p in plugins if p.category != "browser_privacy"]
        plugins = [p for p in plugins if p.category in cfg.mode.enabled_categories]

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        )

        task_map = {p.plugin_id: progress.add_task(p.name, total=1) for p in plugins}

        def on_start(plugin):
            progress.update(task_map[plugin.plugin_id], description=plugin.name)

        def on_complete(plugin, _result):
            progress.update(task_map[plugin.plugin_id], completed=1)

        with progress:
            engine = ScanEngine(ctx, plugins, on_start=on_start, on_complete=on_complete)
            results = await engine.run()

        results_dicts = [r.to_dict() for r in results]
        ctx.set_shared("raw_results", results_dicts)

        entropy = await entropy_plugin().run(ctx)
        entropy.ended_at = entropy.ended_at or datetime.now(timezone.utc).isoformat()
        results.append(entropy)
        results_dicts.append(entropy.to_dict())

        attack_paths = simulate_attack_paths(results_dicts, cfg.mode.name)
        behavioral = analyze_behavioral_patterns(results_dicts, cfg)
        fingerprint_integrity = compute_fingerprint_integrity(results_dicts, cfg.mode.fingerprint_integrity_floor)
        recommendations = build_recommendation_plan(results_dicts)
        visualization = build_visualization_payload(results_dicts, attack_paths)
        monitor_snapshot = None
        if args.monitor or cfg.monitoring.enabled:
            monitor_snapshot = await MonitoringDaemon(cfg, logger).run_once()

        analyzer = ClaudeAnalyzer(cfg.ai, logger)
        ai_analysis = await analyzer.analyze(
            {
                "mode": cfg.mode.name,
                "results": results_dicts,
                "attack_paths": attack_paths,
                "behavioral": behavioral,
                "fingerprint_integrity": fingerprint_integrity,
                "recommendations": recommendations,
                "monitoring": monitor_snapshot,
            }
        )

        output_payload = {
            "mode": cfg.mode.name,
            "results": results_dicts,
            "attack_paths": attack_paths,
            "behavioral": behavioral,
            "fingerprint_integrity": fingerprint_integrity,
            "recommendations": recommendations,
            "visualization": visualization,
            "monitoring": monitor_snapshot,
            "risk_profile": compute_overall_risk_profile(
                results_dicts,
                attack_paths=attack_paths,
                fingerprint_integrity=fingerprint_integrity,
                weights=cfg.mode.severity_bias,
            ),
        }

        json_path = out_dir / "scan_results.json"
        md_path = out_dir / "report.md"
        html_path = out_dir / "report.html"
        pdf_path = out_dir / "report.pdf"

        no_format_flags = not (args.json or args.md or args.html or args.pdf)
        write_json = args.json or no_format_flags
        write_md = args.md or no_format_flags
        write_html = args.html or no_format_flags
        write_pdf = args.pdf
        generated_paths: List[Path] = []

        if write_json:
            json_path.write_text(_json_dump(output_payload), encoding="utf-8")
            console.print(f"[green]JSON report written:[/] {json_path}")
            generated_paths.append(json_path)

        if write_md:
            md = render_markdown(
                results_dicts,
                ai_analysis.raw,
                cfg.report.title,
                attack_paths=attack_paths,
                behavioral=behavioral,
                fingerprint_integrity=fingerprint_integrity,
                recommendations=recommendations,
                visualization=visualization,
                mode_name=cfg.mode.name,
                score_weights=cfg.mode.severity_bias,
            )
            md_path.write_text(md, encoding="utf-8")
            console.print(f"[green]Markdown report written:[/] {md_path}")
            generated_paths.append(md_path)

        if write_html:
            html = render_html(
                results_dicts,
                ai_analysis.raw,
                cfg.report.title,
                attack_paths=attack_paths,
                behavioral=behavioral,
                fingerprint_integrity=fingerprint_integrity,
                recommendations=recommendations,
                visualization=visualization,
                mode_name=cfg.mode.name,
                score_weights=cfg.mode.severity_bias,
            )
            html_path.write_text(html, encoding="utf-8")
            console.print(f"[green]HTML report written:[/] {html_path}")
            generated_paths.append(html_path)

        if write_pdf:
            html = (
                html_path.read_text(encoding="utf-8")
                if html_path.exists()
                else render_html(
                    results_dicts,
                    ai_analysis.raw,
                    cfg.report.title,
                    attack_paths=attack_paths,
                    behavioral=behavioral,
                    fingerprint_integrity=fingerprint_integrity,
                    recommendations=recommendations,
                    visualization=visualization,
                    mode_name=cfg.mode.name,
                    score_weights=cfg.mode.severity_bias,
                )
            )
            if not html_path.exists():
                html_path.write_text(html, encoding="utf-8")
                generated_paths.append(html_path)
            pdf_result = export_pdf(html, str(pdf_path))
            if pdf_result:
                console.print(f"[green]PDF report written:[/] {pdf_path}")
                generated_paths.append(pdf_path)
            else:
                console.print("[yellow]PDF export unavailable. Install weasyprint.[/]")

        _print_run_summary(
            console,
            results_dicts,
            generated_paths,
            ai_analysis.used,
            cfg.mode.name,
            attack_paths,
            fingerprint_integrity,
            monitor_snapshot,
        )


def _json_dump(payload: Dict[str, object]) -> str:
    import json

    return json.dumps(payload, indent=2)


def _print_env_debug(console: Console, cfg) -> None:
    source = cfg.env_path or "not found"
    key_present = bool(cfg.ai.api_key)
    key_len = len(cfg.ai.api_key) if cfg.ai.api_key else 0
    console.print(f"[cyan]Env source:[/] {source}")
    console.print(f"[cyan]ANTHROPIC_API_KEY present:[/] {key_present} (length={key_len})")
    console.print(f"[cyan]ANTHROPIC_MODEL:[/] {cfg.ai.model}")


def _print_run_summary(
    console: Console,
    results: List[Dict],
    generated_paths: List[Path],
    ai_used: bool,
    mode_name: str,
    attack_paths: Dict[str, object],
    fingerprint_integrity: Dict[str, object],
    monitor_snapshot: Dict[str, object] | None,
) -> None:
    score = compute_privacy_score(results)
    summary = risk_summary(results)
    top_findings = _top_findings(results, limit=5)

    stats = Table(show_header=False, box=None, pad_edge=False)
    stats.add_row("Mode", mode_name)
    stats.add_row("Privacy Score", f"[bold]{score}/100[/bold]")
    stats.add_row("Attack Surface", f"{attack_paths.get('attack_surface_score', 0)}/100")
    stats.add_row("Fingerprint Integrity", f"{fingerprint_integrity.get('integrity_score', 0)}/100")
    stats.add_row("Critical", str(summary["critical"]))
    stats.add_row("High", str(summary["high"]))
    stats.add_row("Medium", str(summary["medium"]))
    stats.add_row("Low", str(summary["low"]))
    stats.add_row("AI Analysis", "Enabled" if ai_used else "Unavailable")
    stats.add_row("Live Alerts", str(len((monitor_snapshot or {}).get("alerts", []))))
    console.print(Panel(stats, title="Scan Summary", border_style="cyan"))

    if top_findings:
        table = Table(title="Top Findings", header_style="bold magenta")
        table.add_column("Severity", style="yellow", no_wrap=True)
        table.add_column("Plugin", style="cyan")
        table.add_column("Finding", style="white")
        for finding in top_findings:
            table.add_row(finding["severity"], finding["plugin"], finding["title"])
        console.print(table)
    else:
        console.print("[green]No actionable findings were detected.[/]")

    if generated_paths:
        output_table = Table(title="Generated Files", header_style="bold green")
        output_table.add_column("Path", style="green")
        for path in generated_paths:
            output_table.add_row(str(path))
        console.print(output_table)


def _print_plugin_inventory(console: Console, plugins, mode_name: str) -> None:
    table = Table(title=f"Loaded Plugins ({mode_name})", header_style="bold cyan")
    table.add_column("Plugin ID", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Name", style="white")
    for plugin in plugins:
        table.add_row(plugin.plugin_id, plugin.category, plugin.name)
    console.print(table)


def _top_findings(results: List[Dict], limit: int = 5) -> List[Dict[str, str]]:
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    findings: List[Dict[str, str]] = []
    for result in results:
        plugin = str(result.get("name", "Unknown plugin"))
        for finding in result.get("findings", []):
            findings.append(
                {
                    "severity": str(finding.get("severity", "info")),
                    "title": str(finding.get("title", "Untitled finding")),
                    "plugin": plugin,
                }
            )
    findings.sort(key=lambda item: severity_order.get(item["severity"], 0), reverse=True)
    return findings[:limit]
