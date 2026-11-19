import os
os.environ["USE_ASGI_TRANSPORT"] = "true"

import asyncio
import httpx
from user_service.main import app as user_app

async def main():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=user_app), base_url="http://test") as client:
        res = await client.post("/auth/login", json={"username": "alice", "password": "123"})
        print("Status direct user_app:", res.status_code)
        print("Body direct user_app:", res.json())

if __name__ == "__main__":
    asyncio.run(main())
