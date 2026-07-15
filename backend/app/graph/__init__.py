"""Graph data layer — IT graph, OT graph, and shared store.

Public API:
    - get_it_graph() / get_ot_graph() — access in-memory graphs
    - combined_snapshot() — JSON-serializable snapshot for GET /graph
    - initialize_graphs() — build + persist steady-state graphs if not on disk
    - persist_all() — write both graphs to disk
"""

from app.graph.store import (
    get_it_graph,
    get_ot_graph,
    combined_snapshot,
    persist_all,
    persist_it_graph,
    persist_ot_graph,
    reset_graphs,
    load_graph,
    save_graph,
    IT_NODE_TYPES,
    IT_EDGE_TYPES,
    OT_NODE_TYPES,
    OT_EDGE_TYPES,
    _IT_GRAPH_PATH,
    _OT_GRAPH_PATH,
)
from app.graph.it_graph import build_steady_state_it_graph
from app.graph.ot_graph import build_steady_state_ot_graph


def initialize_graphs(force: bool = False) -> None:
    """Build and persist steady-state graphs if they don't exist on disk.

    Called at FastAPI startup. If force=True, rebuilds even if JSON exists.
    """
    if force or not _IT_GRAPH_PATH.exists():
        it = build_steady_state_it_graph()
        save_graph(it, _IT_GRAPH_PATH)

    if force or not _OT_GRAPH_PATH.exists():
        ot = build_steady_state_ot_graph()
        save_graph(ot, _OT_GRAPH_PATH)

    # Reset in-memory cache so next access loads from disk
    reset_graphs()
