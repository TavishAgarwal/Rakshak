"""RAKSHAK — SIEM Ingestion Adapter.

Parses generic SIEM payloads (e.g. Splunk HEC, Azure Sentinel webhook)
and maps them into internal graph node properties.
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class SiemEventPayload(BaseModel):
    """Generic payload matching Splunk HEC or similar webhook format."""
    entity_id: str
    event_type: str
    
    # Optional raw telemetry fields
    network_bytes: Optional[float] = None
    dns_query: Optional[str] = None
    process_name: Optional[str] = None
    login_hour: Optional[float] = None
    setpoint_value: Optional[float] = None
    setpoint_low: Optional[float] = None
    setpoint_high: Optional[float] = None


class SiemLogRequest(BaseModel):
    time: Optional[float] = None
    host: Optional[str] = None
    source: Optional[str] = None
    sourcetype: Optional[str] = None
    event: SiemEventPayload


def parse_siem_event(payload: SiemLogRequest) -> Dict[str, Any]:
    """Map the incoming SIEM event to graph node update properties.
    
    This function translates raw SIEM fields into the deterministic flags
    expected by RAKSHAK's behavior scorers.
    """
    event = payload.event
    node_updates: Dict[str, Any] = {
        "id": event.entity_id,
        "last_seen": payload.time,
    }
    
    # Very basic static mapping rules for demonstration
    # In a real setup, this would use a streaming rule engine or threshold checks
    
    # Network Mapping
    if event.network_bytes is not None:
        node_updates["network_bytes"] = event.network_bytes
        if event.network_bytes > 500000:
            node_updates.setdefault("network_flags", []).append("large_data_transfer")
            node_updates["data_exfil_bytes"] = event.network_bytes
            
    # Process Mapping
    if event.process_name is not None:
        node_updates["process_name"] = event.process_name
        suspicious = {"mimikatz.exe", "psexec.exe", "powershell.exe -enc"}
        if event.process_name.lower() in suspicious:
            node_updates.setdefault("process_flags", []).append("suspicious_executable")
            node_updates.setdefault("suspicious_processes", []).append(event.process_name)
            
    # DNS Mapping
    if event.dns_query is not None:
        node_updates["dns_query"] = event.dns_query
        if len(event.dns_query) > 25 and "-" in event.dns_query: # naive DGA check
            node_updates.setdefault("dns_flags", []).append("dga_detected")
            node_updates["dga_domain_count"] = 1
            
    # OT Physics Mapping
    if event.setpoint_value is not None:
        node_updates["setpoint_value"] = event.setpoint_value
        if event.setpoint_low is not None and event.setpoint_high is not None:
            if event.setpoint_value < event.setpoint_low or event.setpoint_value > event.setpoint_high:
                node_updates.setdefault("ot_physics_flags", []).append("unauthorized_setpoint_change")
                node_updates["sensor_deviation_pct"] = 0.5  # Fixed high dev for demo
                
    return node_updates
