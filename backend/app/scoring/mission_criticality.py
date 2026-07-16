"""RAKSHAK — Mission criticality vector computation.

Extracts the multi-dimensional criticality vector for an entity from its
graph node attributes.  The vector is NOT a single number — it preserves
the distinct dimensions so the response gate and UI can reason about each.

Dimensions:
    - operational_importance: How critical to ongoing operations (0-1)
    - data_sensitivity: Sensitivity of data handled (0-1)
    - connectivity_risk: Risk from graph connectivity (degree centrality)
    - safety_impact: Physical safety implications (0-1, OT nodes only)
    - recovery_difficulty: How hard to restore if compromised (0-1)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx


@dataclass(frozen=True)
class MissionCriticalityVector:
    """Multi-dimensional criticality assessment for an entity."""

    node_id: str
    operational_importance: float
    data_sensitivity: float
    connectivity_risk: float
    safety_impact: float
    recovery_difficulty: float
    composite_score: float          # weighted combination for quick ranking
    asset_type: str                 # IT / OT / IT_OT_BRIDGE


def compute_criticality(
    node_id: str,
    it_graph: nx.DiGraph,
    ot_graph: nx.DiGraph,
    policy: dict[str, Any] | None = None,
) -> MissionCriticalityVector:
    """Compute the mission criticality vector for a graph entity.

    Uses node attributes set in Phase 1 (mission_criticality, safety_rated,
    trust_level, etc.) plus graph-structural metrics (degree centrality).
    """
    in_it = node_id in it_graph
    in_ot = node_id in ot_graph
    graph = it_graph if in_it else ot_graph
    node = graph.nodes.get(node_id, {})
    node_type = node.get("node_type", "UNKNOWN")

    # Determine asset type
    if node_type == "IT_OT_BRIDGE":
        asset_type = "IT_OT_BRIDGE"
    elif in_ot:
        asset_type = "OT"
    else:
        asset_type = "IT"

    # --- Operational importance ---
    # Directly from the mission_criticality attribute set in Phase 1
    operational_importance = float(node.get("mission_criticality", 0.5))

    # --- Data sensitivity ---
    # Higher for endpoints, cloud resources, applications
    sensitivity_by_type: dict[str, float] = {
        "USER": 0.4, "ENDPOINT": 0.5, "CLOUD_RESOURCE": 0.6,
        "APPLICATION": 0.7, "API": 0.6, "IT_OT_BRIDGE": 0.8,
        "PLC": 0.3, "RTU": 0.3, "HMI": 0.4, "SCADA_SERVER": 0.7,
        "SENSOR": 0.2, "ACTUATOR": 0.3,
    }
    data_sensitivity = sensitivity_by_type.get(node_type, 0.5)

    # --- Connectivity risk ---
    # Degree centrality — more connections = more blast radius
    total_degree = graph.in_degree(node_id) + graph.out_degree(node_id)
    max_possible = max(graph.number_of_nodes() - 1, 1)
    connectivity_risk = min(total_degree / max_possible, 1.0)

    # --- Safety impact ---
    # Only OT nodes can have physical safety implications
    if asset_type == "OT" or asset_type == "IT_OT_BRIDGE":
        safety_rated = bool(node.get("safety_rated", False))
        base_safety = 0.6 if safety_rated else 0.3
        # PLCs and actuators have higher safety impact
        safety_boost: dict[str, float] = {
            "PLC": 0.3, "ACTUATOR": 0.3, "SENSOR": 0.1,
            "SCADA_SERVER": 0.2, "IT_OT_BRIDGE": 0.2,
        }
        safety_impact = min(base_safety + safety_boost.get(node_type, 0.0), 1.0)
    else:
        safety_impact = 0.0

    # --- Recovery difficulty ---
    # Based on node type and infrastructure role
    recovery_by_type: dict[str, float] = {
        "USER": 0.2, "ENDPOINT": 0.3, "CLOUD_RESOURCE": 0.4,
        "APPLICATION": 0.5, "API": 0.4, "IT_OT_BRIDGE": 0.8,
        "PLC": 0.8, "RTU": 0.6, "HMI": 0.4, "SCADA_SERVER": 0.7,
        "SENSOR": 0.3, "ACTUATOR": 0.5,
    }
    recovery_difficulty = recovery_by_type.get(node_type, 0.5)

    # --- Composite score ---
    weights = (policy or {}).get("criticality_weights", {})
    composite = (
        operational_importance * float(weights.get("operational_importance", 0.30))
        + data_sensitivity * float(weights.get("data_sensitivity", 0.15))
        + connectivity_risk * float(weights.get("connectivity_risk", 0.10))
        + safety_impact * float(weights.get("safety_impact", 0.25))
        + recovery_difficulty * float(weights.get("recovery_difficulty", 0.20))
    )

    return MissionCriticalityVector(
        node_id=node_id,
        operational_importance=round(operational_importance, 4),
        data_sensitivity=round(data_sensitivity, 4),
        connectivity_risk=round(connectivity_risk, 4),
        safety_impact=round(safety_impact, 4),
        recovery_difficulty=round(recovery_difficulty, 4),
        composite_score=round(composite, 4),
        asset_type=asset_type,
    )
