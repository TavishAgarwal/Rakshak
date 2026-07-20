"""
RAKSHAK - CERT-In Incident Reporting Workflow
Translates a RAKSHAK GateDecision and CampaignState into a CERT-In mandated format.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app.campaign.state_machine import CampaignStateDistribution
from app.response.gate import GateDecision

def generate_cert_in_report(
    entity: dict[str, Any],
    campaign_state: CampaignStateDistribution,
    gate_decision: GateDecision,
    evidence_sources: list[dict[str, Any]]
) -> dict[str, Any]:
    """Format an incident into the CERT-In incident reporting structure."""
    
    # Map internal types to CERT-In classifications
    incident_type = "Malicious Code / Malware"
    if "network" in [src.get("scorer_class") for src in evidence_sources]:
        incident_type = "Unauthorised Access / Network Scanning"
    if gate_decision.asset_type in ("OT", "IT_OT_BRIDGE"):
        incident_type = "SCADA / Critical Infrastructure Incident"
    
    # Construct standard CERT-In JSON schema
    report = {
        "report_metadata": {
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator_tool": "RAKSHAK Automated Evidence Fusion",
            "reporting_entity_org_id": "national-grid-cni"
        },
        "incident_details": {
            "time_of_occurrence": datetime.now(timezone.utc).isoformat(), # Mocking to current time
            "incident_classification": incident_type,
            "severity": gate_decision.risk_tier.upper(),
            "description": f"Automated detection of {campaign_state.dominant_phase} activity with {campaign_state.dominant_probability:.1%} probability.",
        },
        "affected_systems": [
            {
                "asset_id": gate_decision.node_id,
                "asset_type": gate_decision.asset_type,
                "criticality_score": gate_decision.criticality_composite
            }
        ],
        "indicators_of_compromise": [
            {
                "type": src.get("scorer_class"),
                "score": src.get("raw_score", 0.0),
                "details": src
            } for src in evidence_sources
        ],
        "actions_taken": {
            "automated_containment_actions": gate_decision.allowed_actions,
            "human_escalation_required": gate_decision.requires_human_escalation,
            "blocked_actions_for_safety": gate_decision.blocked_actions,
            "justification": gate_decision.rationale
        },
        "mitre_attck_mapping": {
            "dominant_tactic": campaign_state.dominant_phase,
            "confidence": campaign_state.dominant_probability
        }
    }
    
    return report

