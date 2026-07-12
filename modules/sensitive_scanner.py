# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import asyncio
from core.base_module import BaseAuditModule
from core.http_client import AsyncResilientClient

class SensitiveFileScanner(BaseAuditModule):
    @property
    def name(self) -> str:
        return "Enterprise Sensitive Exposure Scanner"

    @property
    def description(self) -> str:
        return "Pemindaian asinkron dengan Dynamic Wordlist, Anti-WAF, dan JSON Reporting"

    async def run(self, target: str) -> None:
        print(f"\n[*] Memulai Enterprise File Scan pada: {target}")
        base_url = target.rstrip('/')
        
        payloads = self.load_wordlist("sensitive_files.txt")
        if not payloads:
            print("[-] Wordlist sensitive_files.txt tidak ditemukan di folder wordlists!")
            return

        headers = self.get_headers()
        print("-" * 55)

        async def fetch(client, payload):
            test_url = f"{base_url}{payload}"
            status, res_headers, text = await client.get(test_url)
            if status == 200:
                content_type = res_headers.get('Content-Type', '').lower()
                if 'text/html' not in content_type:
                    print(f"[!] [KRITIS] File terekspos: {test_url}")
                    self.add_finding("KRITIS", "File Sensitif Terekspos", test_url)

        async with AsyncResilientClient(headers=headers, limit=30, max_retries=3) as client:
            tasks = [fetch(client, payload) for payload in payloads]
            await asyncio.gather(*tasks)

        if not self.findings:
            print("[+] Target aman dari eksposur file sensitif.")
        print("-" * 55)