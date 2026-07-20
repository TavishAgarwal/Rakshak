"""Unit tests for the probabilistic campaign state machine."""

import pytest
import networkx as nx
from app.campaign.state_machine import compute_campaign_state, CampaignStateDistribution

def test_campaign_state_benign_default():
    it_graph = nx.DiGraph()
    ot_graph = nx.DiGraph()
    
    it_graph.add_node("node1")
    
    state = compute_campaign_state("node1", {}, it_graph, ot_graph)
    assert state.dominant_phase == "benign"
    assert state.dominant_probability == 1.0
    # status doesn't exist on CampaignStateDistribution

def test_campaign_state_initial_access():
    it_graph = nx.DiGraph()
    ot_graph = nx.DiGraph()
    
    # Must add indicator flags for the precondition check to pass
    it_graph.add_node("node1", identity_flags=["phishing_target"])
    scorer_results = {"identity": 0.9, "network": 0.9}
    
    state = compute_campaign_state("node1", scorer_results, it_graph, ot_graph)
    assert state.dominant_phase == "initial_access"
    assert "initial_access" in state.distribution
    assert state.distribution["initial_access"] > 0.5

def test_lateral_movement_requires_precondition():
    it_graph = nx.DiGraph()
    ot_graph = nx.DiGraph()
    
    it_graph.add_node("node1", network_flags=["cross_zone_traffic"])
    
    # High network score but no prior credential access should heavily dampen lateral movement
    scorer_results = {"network": 0.9}
    
    state = compute_campaign_state("node1", scorer_results, it_graph, ot_graph)
    # Without preconditions (credential_access), lateral_movement is blocked
    assert state.distribution.get("lateral_movement", 0.0) == 0.0

def test_impact_triggered_by_ot_physics():
    it_graph = nx.DiGraph()
    ot_graph = nx.DiGraph()
    
    # Add prerequisite phases to satisfy preconditions for impact
    # impact requires lateral_movement, lateral_movement requires credential_access
    # So we'll satisfy it by adding predecessors in the graph
    
    it_graph.add_node("node_it", credential_flags=["credential_dump"])
    ot_graph.add_node("node_bridge", network_flags=["cross_zone_traffic"])
    ot_graph.add_edge("node_it", "node_bridge")
    
    ot_graph.add_node("plc1", ot_physics_flags=["unauthorized_setpoint_change"])
    ot_graph.add_edge("node_bridge", "plc1")
    
    # Need to simulate the scores propagating
    scorer_results = {
        "ot_physics": 0.95,
        "credential": 0.9,
        "network": 0.8
    }
    
    state = compute_campaign_state("plc1", scorer_results, it_graph, ot_graph)
    assert state.dominant_phase == "impact"
    assert state.distribution["impact"] > 0.5
