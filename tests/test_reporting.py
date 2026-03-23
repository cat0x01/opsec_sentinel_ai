from opsec_sentinel_ai.reporting.markdown_report import render_markdown
from opsec_sentinel_ai.reporting.scoring import compute_privacy_score, risk_summary


def _sample_results():
    return [
        {
            "plugin_id": "system.open_ports",
            "name": "Open Local Ports Check",
            "category": "system_opsec",
            "status": "warning",
            "findings": [
                {
                    "id": "ports.listening",
                    "title": "Listening local ports detected",
                    "severity": "medium",
                    "description": "Local services are listening",
                    "recommendation": "Review listeners",
                    "evidence": {"listening": [{"ip": "0.0.0.0", "port": 1515}]},
                }
            ],
        }
    ]


def test_scoring_and_summary() -> None:
    results = _sample_results()
    assert compute_privacy_score(results) == 92
    assert risk_summary(results)["medium"] == 1


def test_markdown_contains_fix_plan_and_commands() -> None:
    results = _sample_results()
    md = render_markdown(results, "AI text", "Report")
    assert "## Priority Fix Plan" in md
    assert "`sudo ss -tulpen`" in md
    assert "1515/tcp" in md
