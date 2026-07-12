# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import asyncio
import re
# pyrefly: ignore [missing-import]
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from core.base_module import BaseAuditModule
from core.http_client import AsyncResilientClient

class JSSecretsScanner(BaseAuditModule):
    @property
    def name(self) -> str:
        return "Frontend JS Secrets & API Key Harvester"

    @property
    def description(self) -> str:
        return "Mengekstrak dan memindai file JavaScript untuk hardcoded credentials"

    async def run(self, target: str) -> None:
        print(f"\n[*] Memulai JS Secrets Harvest pada: {target}")
        base_url = target if target.endswith('/') else f"{target}/"
        headers = self.get_headers()
        
        patterns = {
            "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
            "AWS Access Key": r"(AKIA[0-9A-Z]{16})",
            "AWS Secret Key": r"(?i)aws_secret_access_key\s*[:=]\s*[\'\"]([a-zA-Z0-9/+=]{40})[\'\"]",
            "Stripe Standard API": r"(sk_live_[0-9a-zA-Z]{24})",
            "Stripe Restricted API": r"(rk_live_[0-9a-zA-Z]{24})",
            "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "Firebase URL": r"(.*firebaseio\.com)",
            "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
            "Github Access Token": r"(ghp_[0-9a-zA-Z]{36})",
            "Generic Secret": r"(?i)(?:password|secret|api_key|access_token)\s*[:=]\s*[\'\"]([a-zA-Z0-9\-_]{8,64})[\'\"]"
        }
        
        print("-" * 55)
        js_links = set()

        async with AsyncResilientClient(headers=headers, limit=10, max_retries=2) as client:
            status, res_headers, text = await client.get(base_url)
            if status == 200:
                soup = BeautifulSoup(text, 'html.parser')
                for script in soup.find_all('script'):
                    src = script.get('src')
                    if src:
                        js_links.add(urljoin(base_url, src))
            
            if not js_links:
                print("[+] Tidak ada referensi file JavaScript eksternal yang ditemukan.")
                print("-" * 55)
                return

            print(f"[*] Ditemukan {len(js_links)} file JS. Mengunduh dan memindai secara asinkron...")

            async def scan_js(url):
                status, _, text = await client.get(url)
                if status == 200:
                    for key_name, regex in patterns.items():
                        matches = set(re.findall(regex, text))
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]
                            if len(match) > 4:
                                masked = match[:4] + "*" * (len(match) - 8) + match[-4:] if len(match) > 8 else match
                                print(f"[!] [KRITIS] {key_name} terekspos di: {url}")
                                print(f"    └─ Data: {masked}")
                                self.add_finding("KRITIS", f"Hardcoded {key_name}", f"Ditemukan di {url}. Snippet: {masked}")

            tasks = [scan_js(url) for url in js_links]
            await asyncio.gather(*tasks)

        if not self.findings:
            print("[+] Target aman. Tidak ditemukan hardcoded secrets di frontend.")
        print("-" * 55)