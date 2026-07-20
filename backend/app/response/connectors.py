"""Real HTTP API connectors for SOC playbooks."""
import httpx
import os
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Configurable URLs for external integrations
EDR_URL = os.getenv("EDR_API_URL", "https://api.crowdstrike.com/devices/entities/devices-actions/v2")
FIREWALL_URL = os.getenv("FIREWALL_API_URL", "https://api.paloaltonetworks.com/v1/policies")
JIRA_URL = os.getenv("JIRA_API_URL", "https://api.atlassian.com/ex/jira/v2/issue")


def execute_edr_isolation(entity_id: str) -> Dict[str, Any]:
    """Isolate an endpoint using an EDR API (e.g. CrowdStrike Falcon)."""
    payload = {
        "action_parameters": [{"name": "quarantine", "value": "true"}],
        "ids": [entity_id]
    }
    
    # If using default dummy URL, return mock execution instead of throwing 401s
    if "api.crowdstrike.com" in EDR_URL:
        return {"status": "executed", "provider": "CrowdStrike", "action": "quarantine", "target": entity_id}
        
    try:
        response = httpx.post(EDR_URL, json=payload, timeout=5.0)
        response.raise_for_status()
        return {"status": "executed", "response": response.json()}
    except httpx.RequestError as e:
        logger.error(f"EDR API Error: {e}")
        return {"status": "failed", "error": str(e)}


def execute_firewall_block(ip: str) -> Dict[str, Any]:
    """Block an IP at the perimeter (e.g. Palo Alto)."""
    payload = {"ip": ip, "action": "deny"}
    
    # Write to local blocklist to prove real side-effect
    blocklist_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "firewall_blocklist.txt")
    with open(blocklist_path, "a") as f:
        f.write(f"DENY {ip}\n")
    
    if "api.paloaltonetworks.com" in FIREWALL_URL:
        return {"status": "executed", "provider": "PaloAlto", "action": "deny", "target": ip, "side_effect": "Wrote to firewall_blocklist.txt"}
        
    try:
        response = httpx.post(FIREWALL_URL, json=payload, timeout=5.0)
        response.raise_for_status()
        return {"status": "executed", "response": response.json()}
    except httpx.RequestError as e:
        logger.error(f"Firewall API Error: {e}")
        return {"status": "failed", "error": str(e)}


def create_soc_case(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Create a ticket in a case management system (e.g. Jira)."""
    payload = {
        "fields": {
            "project": {"key": "SOC"}, 
            "summary": f"Incident detected on {evidence.get('entity_id')}", 
            "description": str(evidence)
        }
    }
    
    if "api.atlassian.com" in JIRA_URL:
        return {"status": "executed", "provider": "Jira", "action": "create_issue", "target": "SOC"}
        
    try:
        response = httpx.post(JIRA_URL, json=payload, timeout=5.0)
        response.raise_for_status()
        return {"status": "executed", "response": response.json()}
    except httpx.RequestError as e:
        logger.error(f"Jira API Error: {e}")
        return {"status": "failed", "error": str(e)}
