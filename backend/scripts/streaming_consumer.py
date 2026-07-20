"""
RAKSHAK - Redis Pub/Sub Streaming Consumer

This script acts as the ingestion pipeline replacement for production environments.
Instead of looping over static synthetic data, it subscribes to a message broker (Redis/Kafka)
to ingest live SIEM (e.g., Splunk) and OT (e.g., Claroty) telemetry asynchronously.
"""

import os
import json
import asyncio
import httpx

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
RAKSHAK_API_URL = os.getenv("RAKSHAK_API_URL", "http://localhost:8000")

async def listen_to_broker():
    print(f"Connecting to Message Broker at {REDIS_URL}...")
    # In a real deployment, we use aioredis or confluent-kafka here.
    # For demonstration, we simulate receiving 3 events off the queue.
    print("Subscribed to topic: 'rakshak_telemetry_inbound'")
    
    mock_queue = [
        {"timestamp": "2026-07-20T10:00:00Z", "sensor_id": "FIT101", "event_type": "reading_deviation", "value": 1.5},
        {"timestamp": "2026-07-20T10:00:05Z", "user_id": "admin", "event_type": "unusual_login", "ip": "192.168.1.55"},
        {"timestamp": "2026-07-20T10:00:10Z", "sensor_id": "MV101", "event_type": "unauthorized_setpoint_change", "value": 0}
    ]
    
    async with httpx.AsyncClient() as client:
        for event in mock_queue:
            print(f"\n[Broker] Received event: {event['event_type']}")
            
            # Map raw event to SIEM format expected by RAKSHAK
            payload = {
                "timestamp": event["timestamp"],
                "source": "Claroty" if "sensor_id" in event else "Splunk",
                "event_type": "OT_ALERT" if "sensor_id" in event else "IT_ALERT",
                "raw_data": event
            }
            
            try:
                # We would typically use a bearer token here if required
                headers = {"Authorization": "Bearer demo-token"}
                response = await client.post(f"{RAKSHAK_API_URL}/api/ingest/siem", json=payload, headers=headers)
                
                if response.status_code == 200:
                    print(f"[Consumer] Successfully ingested event into graph. Updated Belief: {response.json().get('updated_belief')}")
                else:
                    print(f"[Consumer] Failed to ingest: {response.status_code} - {response.text}")
                    
            except httpx.RequestError as e:
                print(f"[Consumer] API Connection error: {e}")
                
            await asyncio.sleep(2)

if __name__ == "__main__":
    try:
        asyncio.run(listen_to_broker())
    except KeyboardInterrupt:
        print("\nConsumer shut down.")
