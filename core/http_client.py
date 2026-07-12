# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import asyncio
# pyrefly: ignore [missing-import]
import aiohttp

class AsyncResilientClient:
    def __init__(self, headers=None, limit=50, max_retries=3):
        self.headers = headers or {}
        self.max_retries = max_retries
        self.connector = aiohttp.TCPConnector(limit=limit)
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(connector=self.connector, headers=self.headers)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    async def get(self, url, allow_redirects=False, timeout=10):
        for attempt in range(self.max_retries):
            try:
                async with self.session.get(url, allow_redirects=allow_redirects, timeout=timeout) as response:
                    if response.status == 429:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    text = await response.text()
                    return response.status, response.headers, text
            except Exception:
                if attempt == self.max_retries - 1:
                    return 0, {}, ""
                await asyncio.sleep(2 ** attempt)
        return 0, {}, ""