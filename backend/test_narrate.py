import asyncio
from app.narration.openai_client import narrate, OPENAI_API_KEY, MODEL

async def main():
    print(f"Key present: {bool(OPENAI_API_KEY)}")
    print(f"Model: {MODEL}")
    res = await narrate("node-1", "test query", {"test": "data"})
    print(res)

asyncio.run(main())
