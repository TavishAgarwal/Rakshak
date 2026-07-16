"""RAKSHAK — ATT&CK subgraph matching.

Maps incident events to MITRE ATT&CK technique IDs and checks whether
observed graph paths match known attack patterns.  Used by the campaign
state machine to validate kill-chain progression.

Deterministic graph logic only — no LLM (per rules.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx

# ---------------------------------------------------------------------------
# ATT&CK technique metadata
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttackTechnique:
    """Metadata for a single MITRE ATT&CK technique."""

    technique_id: str
    name: str
    tactic: str
    required_edge_types: list[str]   # graph edge types that evidence this technique


import json
from pathlib import Path

_STIX_PATH = Path(__file__).resolve().parents[2] / "data" / "stix" / "enterprise-attack-subset.json"

def _load_technique_db() -> dict[str, AttackTechnique]:
    """Load ATT&CK techniques from a STIX 2.1 bundle."""
    with open(_STIX_PATH, "r") as f:
        bundle = json.load(f)
    
    db: dict[str, AttackTechnique] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_refs = obj.get("external_references", [])
        tech_id = next((r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"), None)
        if not tech_id:
            continue
        
        kill_chain = obj.get("kill_chain_phases", [{}])
        tactic = kill_chain[0].get("phase_name", "unknown") if kill_chain else "unknown"
        edge_types = obj.get("x_rakshak_required_edge_types", [])
        
        db[tech_id] = AttackTechnique(
            technique_id=tech_id,
            name=obj["name"],
            tactic=tactic,
            required_edge_types=edge_types,
        )
    return db

TECHNIQUE_DB: dict[str, AttackTechnique] = _load_technique_db()


# ---------------------------------------------------------------------------
# Subgraph matching
# ---------------------------------------------------------------------------

def find_attack_path(
    source_id: str,
    target_id: str,
    graph: nx.DiGraph,
    technique_id: str,
) -> dict[str, Any] | None:
    """Check if a graph path from source to target satisfies an ATT&CK technique.

    Returns match details if a valid path exists, None otherwise.
    """
    technique = TECHNIQUE_DB.get(technique_id)
    if technique is None:
        return None

    if source_id not in graph or target_id not in graph:
        return None

    # Check for direct edge
    if graph.has_edge(source_id, target_id):
        edge_data = graph.edges[source_id, target_id]
        edge_type = edge_data.get("edge_type", "")
        if not technique.required_edge_types or edge_type in technique.required_edge_types:
            return {
                "technique_id": technique.technique_id,
                "technique_name": technique.name,
                "tactic": technique.tactic,
                "path": [source_id, target_id],
                "edge_type": edge_type,
                "direct_match": True,
            }

    # Check for shortest path (max 3 hops)
    try:
        path = nx.shortest_path(graph, source_id, target_id)
        if len(path) <= 4:  # max 3 hops
            edge_types = []
            for i in range(len(path) - 1):
                ed = graph.edges.get((path[i], path[i + 1]), {})
                edge_types.append(ed.get("edge_type", "unknown"))
            return {
                "technique_id": technique.technique_id,
                "technique_name": technique.name,
                "tactic": technique.tactic,
                "path": path,
                "edge_types": edge_types,
                "direct_match": False,
            }
    except nx.NetworkXNoPath:
        pass

    return None

