import asyncio
import httpx
import os
from dotenv import load_dotenv

load_dotenv(override=True)

async def main():
    api_key = os.getenv("OPENAI_API_KEY")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "model": "gpt-5-mini",
        "max_completion_tokens": 1024,
        "messages": [
            {"role": "system", "content": "say hi"},
            {"role": "user", "content": "hi"}
        ],
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
        print(f"Status: {resp.status_code}")
        print(resp.text)

asyncio.run(main())
