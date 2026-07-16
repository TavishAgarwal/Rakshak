"""Mock SOAR playbooks used for PS7 automation coverage evidence."""

from __future__ import annotations

from typing import Any

from app.audit.chain import append_audit_entry
from app.response.soar_state import execute_connector_step


ACTIVE_OT_DISRUPTION = {
    "isolate_endpoint",
    "revoke_credential",
    "disable_account",
    "ot_isolate_segment",
    "ot_shutdown_plc",
    "ot_disable_actuator",
}


PLAYBOOKS: dict[str, list[dict[str, Any]]] = {
    "increase_monitoring": [
        {"id": "siem-watchlist", "connector": "SIEM", "description": "Add entity to high-sensitivity watchlist", "autonomous": True},
        {"id": "edr-telemetry", "connector": "EDR", "description": "Increase endpoint telemetry sampling", "autonomous": True},
    ],
    "alert_soc": [
        {"id": "siem-case", "connector": "SIEM", "description": "Open SOC case with evidence bundle", "autonomous": True},
        {"id": "pager-duty", "connector": "OnCall", "description": "Page duty analyst", "autonomous": True},
    ],
    "quarantine_file": [
        {"id": "edr-hash-block", "connector": "EDR", "description": "Block malicious file hash", "autonomous": True},
        {"id": "siem-case", "connector": "SIEM", "description": "Attach file evidence to case", "autonomous": True},
        {"id": "analyst-approve-quarantine", "connector": "SOAR", "description": "Analyst confirms quarantine scope", "autonomous": False},
    ],
    "isolate_endpoint": [
        {"id": "edr-isolate", "connector": "EDR", "description": "Network-isolate endpoint", "autonomous": True},
        {"id": "iam-revoke", "connector": "IAM", "description": "Revoke active user sessions", "autonomous": True},
        {"id": "firewall-block", "connector": "Firewall", "description": "Block observed C2 IPs", "autonomous": True},
        {"id": "owner-notify", "connector": "ITSM", "description": "Notify asset owner", "autonomous": True},
    ],
    "revoke_credential": [
        {"id": "iam-revoke", "connector": "IAM", "description": "Revoke session and rotate credential", "autonomous": True},
        {"id": "siem-case", "connector": "SIEM", "description": "Open credential compromise case", "autonomous": True},
    ],
    "block_ip": [
        {"id": "firewall-block", "connector": "Firewall", "description": "Push deny rule to perimeter firewall", "autonomous": True},
        {"id": "siem-ioc", "connector": "SIEM", "description": "Publish IOC to SIEM watchlist", "autonomous": True},
    ],
    "gateway_air_gap": [
        {"id": "ot-monitoring", "connector": "OT Sensor", "description": "Increase passive OT monitoring", "autonomous": True},
        {"id": "operator-alert", "connector": "HMI", "description": "Alert control-room operator", "autonomous": True},
        {"id": "gateway-rule-approval", "connector": "SOAR", "description": "Request approval before gateway isolation", "autonomous": False},
    ],
    "passive_monitoring": [
        {"id": "ot-monitoring", "connector": "OT Sensor", "description": "Increase passive OT monitoring", "autonomous": True},
        {"id": "operator-alert", "connector": "HMI", "description": "Alert control-room operator", "autonomous": True},
    ],
    "ot_shutdown_plc": [
        {"id": "ot-shutdown-plc", "connector": "PLC", "description": "Shutdown PLC", "autonomous": False},
    ],
}


def is_ot_entity(entity: dict[str, Any]) -> bool:
    node_type = entity.get("node_type", "")
    asset_type = entity.get("graph_domain", "")
    return asset_type in ("OT", "IT_OT_BRIDGE") or node_type in {
        "PLC",
        "RTU",
        "HMI",
        "SENSOR",
        "ACTUATOR",
        "SCADA_SERVER",
        "IT_OT_BRIDGE",
    }


def run_mock_playbook(
    entity: dict[str, Any],
    action: str,
    evidence_sources: list[dict[str, Any]] | None = None,
    audit: bool = False,
    execute: bool = False,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Preview or execute a mock SOAR playbook and compute autonomous coverage."""
    evidence_sources = evidence_sources or []
    steps = PLAYBOOKS.get(action, PLAYBOOKS["alert_soc"])
    is_ot = is_ot_entity(entity)
    step_results: list[dict[str, Any]] = []

    for step in steps:
        if is_ot and action in ACTIVE_OT_DISRUPTION:
            status = "blocked"
            detail = "OT active disruption is structurally blocked"
        elif step["autonomous"]:
            if execute:
                connector_result = execute_connector_step(entity, step)
                status = connector_result["status"]
                detail = connector_result["detail"]
            else:
                status = "executed"
                detail = f"Local {step['connector']} connector is executable"
        else:
            status = "requires_approval"
            detail = "Human approval required by policy"

        result = {
            **step,
            "status": status,
            "detail": detail,
        }
        step_results.append(result)

        if audit:
            append_audit_entry(
                entity_id=entity.get("id", "unknown"),
                evidence_sources=evidence_sources,
                alternatives_considered=[],
                human_approval={
                    "approved_by": "auto_executed" if status == "executed" else None,
                    "timestamp": None,
                },
                action_taken=action,
                event_type="playbook_step",
                playbook_step_id=step["id"],
                step_status=status,
                source_refs=[src.get("source", src.get("scorer_class", "unknown")) for src in evidence_sources],
                metadata={"connector": step["connector"], "detail": detail},
                **(context or {}),
            )

    executed = sum(1 for step in step_results if step["status"] == "executed")
    total = len(step_results)
    return {
        "action": action,
        "steps": step_results,
        "autonomous_steps": executed,
        "total_steps": total,
        "automation_coverage": round(executed / total, 3) if total else 0.0,
    }
