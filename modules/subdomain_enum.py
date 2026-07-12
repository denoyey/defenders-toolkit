# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import asyncio
import json
from urllib.parse import urlparse
from core.base_module import BaseAuditModule
from core.http_client import AsyncResilientClient

class SubdomainEnumerator(BaseAuditModule):
    @property
    def name(self) -> str:
        return "OSINT Subdomain Enumerator"

    @property
    def description(self) -> str:
        return "Mengekstrak subdomain dari Certificate Transparency logs (crt.sh)"

    async def run(self, target: str) -> None:
        parsed = urlparse(target)
        domain = parsed.netloc if parsed.netloc else parsed.path
        domain = domain.replace("www.", "").split(":")[0]
        
        print(f"\n[*] Memulai OSINT Subdomain Enumeration untuk: {domain}")
        headers = self.get_headers()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        async with AsyncResilientClient(headers=headers, limit=5, max_retries=3) as client:
            status, res_headers, text = await client.get(url, timeout=30)
            
            if status == 200 and text:
                try:
                    data = json.loads(text)
                    subdomains = set()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            clean_sub = sub.strip().replace("*.", "")
                            if clean_sub.endswith(domain) and clean_sub != domain:
                                subdomains.add(clean_sub)
                    
                    if subdomains:
                        print(f"[+] Ditemukan {len(subdomains)} subdomain unik.\n")
                        for sub in sorted(subdomains):
                            print(f"    └─ {sub}")
                            self.add_finding("INFO", "Subdomain Ditemukan", sub)
                    else:
                        print("[-] Tidak ditemukan subdomain.")
                except ValueError:
                    print("[-] Gagal memparsing data respons dari crt.sh.")
            else:
                print(f"[-] Gagal menghubungi crt.sh (Status: {status})")
        
        print("-" * 55)