"""Mock EDR Service for PS7 system boundary demonstration."""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="Mock EDR API")

class IsolateRequest(BaseModel):
    entity_id: str
    reason: str

isolated_entities: set[str] = set()

@app.post("/quarantine")
async def quarantine_endpoint(req: IsolateRequest):
    if req.entity_id in isolated_entities:
        return {"status": "skipped", "detail": f"{req.entity_id} is already isolated."}
    
    isolated_entities.add(req.entity_id)
    print(f"[EDR MOCK] Isolated {req.entity_id} for reason: {req.reason}")
    return {"status": "executed", "detail": f"Successfully isolated {req.entity_id}"}

@app.get("/status/{entity_id}")
async def get_status(entity_id: str):
    if entity_id in isolated_entities:
        return {"status": "isolated"}
    return {"status": "active"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
