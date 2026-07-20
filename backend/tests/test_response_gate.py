import pytest
from app.response.gate import assert_action_allowed, evaluate_gate, GateDecision

def test_ot_disruptive_action_raises_value_error():
    ot_entity = {"id": "plc-1", "node_type": "PLC", "graph_domain": "OT"}
    with pytest.raises(ValueError, match="CRITICAL SAFETY VIOLATION"):
        assert_action_allowed(ot_entity, "ot_shutdown_plc")
        
    with pytest.raises(ValueError, match="CRITICAL SAFETY VIOLATION"):
        assert_action_allowed(ot_entity, "ot_isolate_segment")

def test_non_ot_action_on_ot_asset_blocked():
    # evaluate_gate hard blocks OT_ACTIVE_DISRUPTION and allows OT_SAFE_ACTIONS.
    # Non-OT actions (IT actions like isolate_endpoint) are not in OT_SAFE_ACTIONS or OT_ACTIVE_DISRUPTION,
    # wait, the code checks `assert_action_allowed` which blocks 'isolate_endpoint' as well.
    ot_entity = {"id": "plc-1", "node_type": "PLC", "graph_domain": "OT"}
    with pytest.raises(ValueError, match="CRITICAL SAFETY VIOLATION"):
        assert_action_allowed(ot_entity, "isolate_endpoint")

def test_it_action_on_it_asset_allowed():
    it_entity = {"id": "ep-1", "node_type": "ENDPOINT", "graph_domain": "IT"}
    # Should not raise
    assert_action_allowed(it_entity, "isolate_endpoint")

def test_evaluate_gate_logic():
    decision = evaluate_gate(
        node_id="plc-1",
        asset_type="OT",
        confidence=0.9,
        criticality_composite=0.5,
        safety_impact=0.8
    )
    assert "ot_shutdown_plc" in decision.blocked_actions
    assert decision.requires_human_escalation == True
    
    it_decision = evaluate_gate(
        node_id="ep-1",
        asset_type="IT",
        confidence=0.9,
        criticality_composite=0.5,
        safety_impact=0.1
    )
    assert "isolate_endpoint" in it_decision.allowed_actions
    assert it_decision.requires_human_escalation == False
