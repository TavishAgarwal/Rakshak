"""RAKSHAK — NetworkX graph load/save and node/edge schema.

Central graph store managing two separate NetworkX DiGraphs (IT and OT).
Persistence is JSON-on-disk. The two graphs are never merged into a single
object — correlation happens only through IT_OT_BRIDGE nodes that exist in
both graphs with matching IDs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import networkx as nx
from networkx.readwrite import json_graph

# ---------------------------------------------------------------------------
# Persistence directory — defaults to backend/data/runtime/graphs/
# ---------------------------------------------------------------------------
_DATA_DIR = Path(os.getenv("RAKSHAK_DATA_DIR", Path(__file__).resolve().parents[2] / "data" / "runtime" / "graphs"))
_IT_GRAPH_PATH = _DATA_DIR / "it_graph.json"
_OT_GRAPH_PATH = _DATA_DIR / "ot_graph.json"
DEFAULT_GRAPH_CONTEXT = {
    "org_id": "national-grid-cni",
    "facility_id": "grid-west-01",
    "sector": "power",
    "policy_id": "power_grid",
}


# ---------------------------------------------------------------------------
# Node type enums (kept as plain strings — no enum import needed)
# ---------------------------------------------------------------------------

# IT-domain node types
IT_NODE_TYPES: list[str] = [
    "USER",
    "ENDPOINT",
    "CLOUD_RESOURCE",
    "APPLICATION",
    "API",
    "IT_OT_BRIDGE",
]

# OT-domain node types
OT_NODE_TYPES: list[str] = [
    "PLC",
    "RTU",
    "HMI",
    "SCADA_SERVER",
    "SENSOR",
    "ACTUATOR",
    "IT_OT_BRIDGE",
]

# IT-domain edge types
IT_EDGE_TYPES: list[str] = [
    "AUTHENTICATES_TO",
    "ACCESSES",
    "TRUST_LEVEL",
    "SECURITY_ZONE",
    "DATA_FLOW",
    "LATERAL_MOVEMENT",
]

# OT-domain edge types
OT_EDGE_TYPES: list[str] = [
    "PHYSICAL_PROCESS_LINK",
    "SAFETY_INTERLOCK",
    "CONTROLS",
    "MONITORS",
    "FIELDBUS_LINK",
    "REDUNDANCY_PAIR",
]


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _graph_to_dict(g: nx.DiGraph) -> dict[str, Any]:
    """Serialize a NetworkX DiGraph to a JSON-compatible dict."""
    return json_graph.node_link_data(g)


def _dict_to_graph(data: dict[str, Any]) -> nx.DiGraph:
    """Deserialize a JSON-compatible dict back into a NetworkX DiGraph."""
    return json_graph.node_link_graph(data, directed=True, multigraph=False)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_graph(g: nx.DiGraph, path: Path) -> None:
    """Persist a NetworkX graph to JSON on disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_graph_to_dict(g), f, indent=2, default=str)


def load_graph(path: Path) -> nx.DiGraph:
    """Load a NetworkX graph from a JSON file. Returns empty DiGraph if not found."""
    if not path.exists():
        return nx.DiGraph()
    with open(path, "r", encoding="utf-8") as f:
        return _dict_to_graph(json.load(f))


# ---------------------------------------------------------------------------
# Graph store — singleton-style holders
# ---------------------------------------------------------------------------

_it_graph: nx.DiGraph | None = None
_ot_graph: nx.DiGraph | None = None


def get_it_graph() -> nx.DiGraph:
    """Return the in-memory IT graph, loading from disk on first access."""
    global _it_graph
    if _it_graph is None:
        _it_graph = load_graph(_IT_GRAPH_PATH)
    return _it_graph


def get_ot_graph() -> nx.DiGraph:
    """Return the in-memory OT graph, loading from disk on first access."""
    global _ot_graph
    if _ot_graph is None:
        _ot_graph = load_graph(_OT_GRAPH_PATH)
    return _ot_graph


def persist_it_graph() -> None:
    """Write the current IT graph to disk."""
    save_graph(get_it_graph(), _IT_GRAPH_PATH)


def persist_ot_graph() -> None:
    """Write the current OT graph to disk."""
    save_graph(get_ot_graph(), _OT_GRAPH_PATH)


def persist_all() -> None:
    """Write both graphs to disk."""
    persist_it_graph()
    persist_ot_graph()


def reset_graphs() -> None:
    """Clear in-memory graphs (useful for tests and re-initialization)."""
    global _it_graph, _ot_graph
    _it_graph = None
    _ot_graph = None


# ---------------------------------------------------------------------------
# Combined snapshot for GET /graph
# ---------------------------------------------------------------------------

def combined_snapshot() -> dict[str, Any]:
    """Return both graphs as a single JSON-serializable dict.

    Each node carries a `graph_domain` field ("IT" or "OT") so the frontend
    can distinguish them without inspecting types.
    """
    it = get_it_graph()
    ot = get_ot_graph()

    it_data = _graph_to_dict(it)
    ot_data = _graph_to_dict(ot)

    # Tag every node with its domain
    for node in it_data.get("nodes", []):
        node["graph_domain"] = "IT"
        for key, value in DEFAULT_GRAPH_CONTEXT.items():
            node.setdefault(key, value)
    for node in ot_data.get("nodes", []):
        node["graph_domain"] = "OT"
        for key, value in DEFAULT_GRAPH_CONTEXT.items():
            node.setdefault(key, value)

    return {
        "it_graph": it_data,
        "ot_graph": ot_data,
        "meta": {
            "it_node_count": it.number_of_nodes(),
            "it_edge_count": it.number_of_edges(),
            "ot_node_count": ot.number_of_nodes(),
            "ot_edge_count": ot.number_of_edges(),
        },
    }
