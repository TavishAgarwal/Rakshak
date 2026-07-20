import pytest
from app.response.connectors import execute_edr_isolation, execute_firewall_block, create_soc_case

def test_execute_edr_isolation():
    # Since it's using the default URL 'api.crowdstrike.com', it returns a mocked success
    res = execute_edr_isolation("test-endpoint-01")
    assert res["status"] == "executed"
    assert res["action"] == "quarantine"

def test_execute_firewall_block():
    res = execute_firewall_block("10.0.0.1")
    assert res["status"] == "executed"
    assert res["action"] == "deny"

def test_create_soc_case():
    res = create_soc_case({"entity_id": "test-endpoint"})
    assert res["status"] == "executed"
    assert res["action"] == "create_issue"
