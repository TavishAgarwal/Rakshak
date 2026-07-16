"""MITRE ATT&CK graph traversal matching for released telemetry."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

import networkx as nx


DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "stix"
ATTACK_CACHE = DATA_DIR / "enterprise-attack.json"
ATTACK_SUBSET = DATA_DIR / "enterprise-attack-subset.json"
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

PHASE_ORDER = [
    "initial-access",
    "credential-access",
    "discovery",
    "lateral-movement",
    "privilege-escalation",
    "collection",
    "exfiltration",
    "impact",
]


def ensure_attack_cache(download: bool = False) -> Path:
    """Return a local STIX bundle, downloading the full bundle when requested."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if download and not ATTACK_CACHE.exists():
        # Build-time helper; runtime works offline from the checked-in subset.
        with urllib.request.urlopen(ATTACK_URL, timeout=20) as response:
            ATTACK_CACHE.write_bytes(response.read())
    return ATTACK_CACHE if ATTACK_CACHE.exists() else ATTACK_SUBSET


def _technique_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _phase(obj: dict[str, Any]) -> str:
    phases = obj.get("kill_chain_phases") or []
    return phases[0].get("phase_name", "unknown") if phases else "unknown"


def load_attack_graph() -> nx.DiGraph:
    """Build a lightweight technique transition graph from STIX."""
    with open(ensure_attack_cache(), "r", encoding="utf-8") as f:
        bundle = json.load(f)

    graph = nx.DiGraph()
    techniques: list[tuple[str, str]] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        tech_id = _technique_id(obj)
        if not tech_id:
            continue
        phase = _phase(obj)
        graph.add_node(tech_id, name=obj.get("name", tech_id), phase=phase)
        techniques.append((tech_id, phase))
        if "." in tech_id:
            parent = tech_id.split(".", 1)[0]
            graph.add_edge(parent, tech_id, edge_type="subtechnique")
            graph.add_edge(tech_id, parent, edge_type="subtechnique")

    phase_rank = {phase: idx for idx, phase in enumerate(PHASE_ORDER)}
    for src, src_phase in techniques:
        for dst, dst_phase in techniques:
            if src == dst:
                continue
            if phase_rank.get(dst_phase, -1) == phase_rank.get(src_phase, -1) + 1:
                graph.add_edge(src, dst, edge_type="kill_chain")
    return graph


def _path_prefix_score(graph: nx.DiGraph, observed: list[str]) -> float:
    if len(observed) <= 1:
        return 1.0 if observed else 0.0
    valid = 0
    for src, dst in zip(observed, observed[1:]):
        if src == dst or graph.has_edge(src, dst):
            valid += 1
            continue
        try:
            if nx.shortest_path_length(graph, src, dst) <= 3:
                valid += 1
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass
    return valid / (len(observed) - 1)


def match_campaign(entity_event_sequence: list[dict[str, Any]], confidence_floor: float = 0.2) -> dict[str, Any]:
    """Match released events to ATT&CK techniques using graph traversal."""
    graph = load_attack_graph()
    evidence = [
        event for event in entity_event_sequence
        if event.get("mitre_technique") and event.get("mitre_technique") in graph
    ]
    raw_evidence = [
        {
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
            "technique": event.get("mitre_technique"),
            "phase": event.get("mitre_phase"),
            "description": event.get("description"),
        }
        for event in entity_event_sequence
        if event.get("mitre_technique")
    ]
    if not evidence:
        return {"status": "unattributed", "raw_evidence": raw_evidence, "matched_techniques": [], "campaign_state": {"benign": 1.0}}

    observed = [event["mitre_technique"] for event in evidence]
    structural_confidence = _path_prefix_score(graph, observed)
    if structural_confidence < confidence_floor:
        return {"status": "unattributed", "raw_evidence": raw_evidence, "matched_techniques": [], "campaign_state": {"benign": 1.0}}

    phase_counts = {phase: 0.0 for phase in PHASE_ORDER}
    matched = []
    for idx, event in enumerate(evidence, start=1):
        tech_id = event["mitre_technique"]
        phase = graph.nodes[tech_id].get("phase", event.get("mitre_phase") or "unknown")
        weight = 1.0 + idx / len(evidence)
        if phase in phase_counts:
            phase_counts[phase] += weight
        matched.append(
            {
                "technique_id": tech_id,
                "technique_name": graph.nodes[tech_id].get("name", tech_id),
                "phase": phase,
                "event_type": event.get("event_type"),
                "description": event.get("description"),
            }
        )

    total = sum(phase_counts.values()) or 1.0
    distribution = {phase: round(value / total, 4) for phase, value in phase_counts.items()}
    distribution["benign"] = 0.0
    dominant_phase = max(distribution, key=distribution.get)
    return {
        "status": "matched",
        "confidence": round(structural_confidence, 4),
        "matched_techniques": matched,
        "campaign_state": distribution,
        "dominant_phase": dominant_phase,
        "dominant_probability": distribution[dominant_phase],
        "raw_evidence": raw_evidence,
    }
