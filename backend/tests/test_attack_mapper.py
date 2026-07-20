import pytest
import networkx as nx
from app.campaign.attack_mapper import find_attack_path, TECHNIQUE_DB, AttackTechnique
import app.campaign.attack_mapper as attack_mapper

@pytest.fixture(autouse=True)
def inject_mock_techniques():
    original = attack_mapper.TECHNIQUE_DB
    attack_mapper.TECHNIQUE_DB = {
        "T-TEST-1": AttackTechnique(
            technique_id="T-TEST-1",
            name="Test Technique 1",
            tactic="test-tactic",
            required_edge_types=["ACCESSES", "TRUST_LEVEL"]
        )
    }
    yield
    attack_mapper.TECHNIQUE_DB = original

def test_find_attack_path_direct_match():
    g = nx.DiGraph()
    g.add_node("A")
    g.add_node("B")
    g.add_edge("A", "B", edge_type="ACCESSES")
    
    match = find_attack_path("A", "B", g, "T-TEST-1")
    assert match is not None
    assert match["direct_match"] is True
    assert match["edge_type"] == "ACCESSES"

def test_find_attack_path_shortest_path_match():
    g = nx.DiGraph()
    g.add_nodes_from(["A", "B", "C"])
    g.add_edge("A", "B", edge_type="ACCESSES")
    g.add_edge("B", "C", edge_type="TRUST_LEVEL")
    
    match = find_attack_path("A", "C", g, "T-TEST-1")
    assert match is not None
    assert match["direct_match"] is False
    assert match["path"] == ["A", "B", "C"]
    assert match["edge_types"] == ["ACCESSES", "TRUST_LEVEL"]

def test_find_attack_path_negative_no_path():
    g = nx.DiGraph()
    g.add_nodes_from(["A", "B", "C"])
    # No path between A and C
    g.add_edge("A", "B", edge_type="ACCESSES")
    
    match = find_attack_path("A", "C", g, "T-TEST-1")
    assert match is None
