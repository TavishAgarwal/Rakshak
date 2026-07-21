import time
import sys
import random
import networkx as nx
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.campaign.attack_mapper import find_attack_path
from scripts.benchmark_networkx import scale_graph
from app.graph.it_graph import build_steady_state_it_graph

def main():
    it_base = build_steady_state_it_graph()
    multiplier = 5000
    graph_di = scale_graph(it_base, multiplier)
    # Convert to undirected so BFS actually has to explore the giant component
    graph = graph_di.to_undirected()
    
    node_list = list(graph.nodes())
    for u, v in graph.edges():
        if "edge_type" not in graph[u][v]:
            graph[u][v]["edge_type"] = "network_connection"
            
    print("\n--- WORST CASE (Undirected, Exhaustive Search) ---")
    src = node_list[0]
    tgt = node_list[-1]
    
    start_worst = time.perf_counter()
    try:
        res = find_attack_path(src, tgt, graph, "T1059")
        found = res is not None
    except Exception as e:
        found = False
    end_worst = time.perf_counter()
    print(f"Worst-case latency (undirected): {(end_worst - start_worst)*1000:.4f} ms (Path found: {found})")

if __name__ == "__main__":
    main()
