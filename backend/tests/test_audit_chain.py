import pytest
import os
import json
import hashlib
from app.audit.chain import append_audit_entry, verify_audit_chain, clear_audit_chain, _CHAIN_FILE
import app.audit.chain as chain_module

@pytest.fixture(autouse=True)
def setup_audit_env(tmp_path):
    # Override chain file to a temp file
    temp_chain = tmp_path / "audit_chain.jsonl"
    old_file = chain_module._CHAIN_FILE
    chain_module._CHAIN_FILE = str(temp_chain)
    clear_audit_chain()
    yield
    chain_module._CHAIN_FILE = old_file

def test_audit_chain_sequential_and_verify():
    # Append 3 entries
    for i in range(3):
        append_audit_entry(
            entity_id=f"node-{i}",
            evidence_sources=[],
            alternatives_considered=[],
            human_approval={},
            action_taken=f"action-{i}"
        )
        
    verification = verify_audit_chain()
    assert verification["valid"] == True
    assert verification["total_verified"] == 3

def test_audit_chain_tampering_detection():
    # Append an entry
    append_audit_entry(
        entity_id="node-1",
        evidence_sources=[],
        alternatives_considered=[],
        human_approval={},
        action_taken="action-1"
    )
    
    # Tamper with the file directly
    with open(chain_module._CHAIN_FILE, "r") as f:
        lines = f.readlines()
        
    tampered_entry = json.loads(lines[0])
    tampered_entry["action_taken"] = "malicious_action"
    lines[0] = json.dumps(tampered_entry) + "\n"
    
    with open(chain_module._CHAIN_FILE, "w") as f:
        f.writelines(lines)
        
    verification = verify_audit_chain()
    assert verification["valid"] == False
    assert "Hash mismatch" in verification["reason"]
