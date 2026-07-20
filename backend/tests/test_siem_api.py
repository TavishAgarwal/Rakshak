import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token

client = TestClient(app)

def test_ingest_siem():
    token = create_access_token(data={"sub": "operator", "role": "operator"})
    headers = {"Authorization": f"Bearer {token}"}
    
    payload = {
        "time": 123456789.0,
        "event": {
            "entity_id": "AuthServer-03",
            "event_type": "process_creation",
            "process_name": "mimikatz.exe"
        }
    }
    
    response = client.post("/api/ingest/siem", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "ingested"
    assert response.json()["entity_id"] == "AuthServer-03"
    assert "updated_belief" in response.json()
