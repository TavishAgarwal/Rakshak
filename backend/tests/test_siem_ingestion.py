from app.ingestion.siem import SiemLogRequest, parse_siem_event

def test_parse_siem_event_mimikatz():
    payload = SiemLogRequest(**{
        "time": 123456789.0,
        "event": {
            "entity_id": "AuthServer-03",
            "event_type": "process_creation",
            "process_name": "mimikatz.exe"
        }
    })
    
    updates = parse_siem_event(payload)
    assert updates["id"] == "AuthServer-03"
    assert "suspicious_executable" in updates["process_flags"]
    assert "mimikatz.exe" in updates["suspicious_processes"]

def test_parse_siem_event_large_transfer():
    payload = SiemLogRequest(**{
        "time": 123456789.0,
        "event": {
            "entity_id": "DBServer-01",
            "event_type": "network_flow",
            "network_bytes": 1000000.0
        }
    })
    
    updates = parse_siem_event(payload)
    assert updates["id"] == "DBServer-01"
    assert "large_data_transfer" in updates["network_flags"]
    assert updates["data_exfil_bytes"] == 1000000.0
