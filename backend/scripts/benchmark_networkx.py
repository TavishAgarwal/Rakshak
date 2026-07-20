import time
import tracemalloc
import random
import networkx as nx
import json
from pathlib import Path
import sys

# Add backend directory to sys.path so we can import app
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.graph.it_graph import build_steady_state_it_graph
from app.graph.ot_graph import build_steady_state_ot_graph

def scale_graph(base_graph: nx.DiGraph, multiplier: int) -> nx.DiGraph:
    """Scale a base graph by duplicating it `multiplier` times and adding cross-edges."""
    scaled = nx.DiGraph()
    
    # Fast copy
    for i in range(multiplier):
        suffix = f"_dup{i}"
        for node, data in base_graph.nodes(data=True):
            scaled.add_node(f"{node}{suffix}", **data)
        for u, v, data in base_graph.edges(data=True):
            scaled.add_edge(f"{u}{suffix}", f"{v}{suffix}", **data)
            
        # Add a few cross edges to make it one giant connected component
        if i > 0:
            nodes_prev = list(base_graph.nodes())
            nodes_curr = list(base_graph.nodes())
            
            for _ in range(5):
                u = random.choice(nodes_prev)
                v = random.choice(nodes_curr)
                scaled.add_edge(f"{u}_dup{i-1}", f"{v}_dup{i}", edge_type="LATERAL_MOVEMENT")

    return scaled

def run_benchmark():
    print("Building base graphs...")
    it_base = build_steady_state_it_graph()
    
    multiplier = 5000  # Scale IT graph (19 nodes) to ~100,000 nodes
    
    tracemalloc.start()
    start_time = time.time()
    
    print(f"Scaling graph by {multiplier}x...")
    scaled_it = scale_graph(it_base, multiplier)
    
    build_time = time.time() - start_time
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    
    print(f"Graph nodes: {scaled_it.number_of_nodes()}")
    print(f"Graph edges: {scaled_it.number_of_edges()}")
    print(f"Peak memory: {peak_mem / 10**6:.2f} MB")
    
    nodes = list(scaled_it.nodes())
    
    # Path finding benchmark
    queries = 5000
    print(f"Running {queries} shortest path queries...")
    
    path_start = time.time()
    found = 0
    
    # Warmup and real test
    for _ in range(queries):
        src = random.choice(nodes)
        tgt = random.choice(nodes)
        try:
            path = nx.shortest_path(scaled_it, src, tgt)
            if len(path) <= 4:
                found += 1
        except nx.NetworkXNoPath:
            pass
            
    path_time = time.time() - path_start
    avg_latency_ms = (path_time / queries) * 1000
    
    tracemalloc.stop()
    
    results = {
        "nodes": scaled_it.number_of_nodes(),
        "edges": scaled_it.number_of_edges(),
        "peak_memory_mb": round(peak_mem / 10**6, 2),
        "build_time_sec": round(build_time, 2),
        "path_queries": queries,
        "avg_latency_ms": round(avg_latency_ms, 3),
        "paths_found": found
    }
    
    print(json.dumps(results, indent=2))
    
    # Write to a file for evidence
    out_dir = Path(__file__).resolve().parent.parent / "data" / "benchmarks"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "networkx_scalability.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"Saved results to {out_path}")

if __name__ == "__main__":
    run_benchmark()
