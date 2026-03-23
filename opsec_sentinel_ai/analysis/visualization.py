from __future__ import annotations

from typing import Any, Dict, List


def build_visualization_payload(results: List[Dict[str, Any]], attack_paths: Dict[str, Any]) -> Dict[str, Any]:
    nodes = [{"id": "operator", "type": "actor", "label": "Operator"}]
    edges = []
    heatmap = []

    for result in results:
        node_id = str(result.get("plugin_id", "unknown"))
        nodes.append({"id": node_id, "type": "signal", "label": result.get("name", node_id)})
        edges.append({"source": "operator", "target": node_id, "kind": "observed"})
        severity_weight = sum(
            {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(finding.get("severity")), 0)
            for finding in result.get("findings", [])
        )
        heatmap.append({"plugin_id": node_id, "weight": severity_weight, "category": result.get("category")})

    for scenario in attack_paths.get("scenarios", []):
        scenario_id = scenario["scenario_id"]
        nodes.append({"id": scenario_id, "type": "scenario", "label": scenario["name"]})
        for supporting in scenario.get("supporting_findings", []):
            edges.append({"source": supporting["plugin_id"], "target": scenario_id, "kind": "supports"})

    return {"nodes": nodes, "edges": edges, "heatmap": heatmap}
