# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import asyncio
import socket
import json
from urllib.parse import urlparse
from core.base_module import BaseAuditModule
from core.http_client import AsyncResilientClient

class WAFOriginDiscovery(BaseAuditModule):
    @property
    def name(self) -> str:
        return "WAF Origin IP Discovery (OSINT)"

    @property
    def description(self) -> str:
        return "Melacak IP asli server di balik WAF menggunakan DNS History dan Shodan InternetDB"

    async def run(self, target: str) -> None:
        parsed = urlparse(target)
        domain = parsed.netloc if parsed.netloc else parsed.path
        domain = domain.replace("www.", "").split(":")[0]

        print(f"\n[*] Memulai WAF Origin Discovery untuk: {domain}")
        headers = self.get_headers()
        
        try:
            current_ip = await asyncio.to_thread(socket.gethostbyname, domain)
            print(f"[*] Resolusi DNS saat ini (Potensi WAF IP): \033[96m{current_ip}\033[0m")
        except Exception:
            current_ip = None
            print(f"[-] Gagal me-resolve IP utama untuk {domain}")

        print("-" * 55)
        
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        
        async with AsyncResilientClient(headers=headers, limit=5, max_retries=3) as client:
            status, res_headers, text = await client.get(url, timeout=20)
            
            potential_ips = set()
            if status == 200 and text and "error" not in text.lower():
                lines = text.strip().split('\n')
                for line in lines:
                    parts = line.split(',')
                    if len(parts) == 2:
                        ip = parts[1].strip()
                        if ip != current_ip and ip != "127.0.0.1":
                            potential_ips.add(ip)
            
            if not potential_ips:
                print("[+] Tidak ditemukan potensi Origin IP (Infrastruktur aman).")
            else:
                print(f"[*] Ditemukan {len(potential_ips)} potensi IP Historis/Subdomain. Memvalidasi paparan publik...")
                
                async def check_shodan_internetdb(ip):
                    shodan_url = f"https://internetdb.shodan.io/{ip}"
                    s_status, _, s_text = await client.get(shodan_url, timeout=10)
                    if s_status == 200:
                        try:
                            data = json.loads(s_text)
                            ports = data.get("ports", [])
                            hostnames = data.get("hostnames", [])
                            cpes = data.get("cpes", [])
                            
                            if ports:
                                print(f"[!] [\033[91mKRITIS\033[0m] Potensi Origin IP Terbuka: \033[93m{ip}\033[0m")
                                print(f"    ├─ Port Terbuka : {ports}")
                                if hostnames:
                                    print(f"    ├─ Hostnames    : {hostnames[:2]}")
                                if cpes:
                                    print(f"    └─ Deteksi CPE  : {cpes[:2]}")
                                else:
                                    print(f"    └─ Deteksi CPE  : Unknown")
                                    
                                self.add_finding(
                                    "KRITIS", 
                                    "WAF Bypass / Origin IP Exposure", 
                                    f"IP asli terekspos: {ip} dengan port {ports}"
                                )
                        except json.JSONDecodeError:
                            pass

                tasks = [check_shodan_internetdb(ip) for ip in potential_ips]
                await asyncio.gather(*tasks)

        if not self.findings:
            print("[+] Konfigurasi jaringan aman. Origin IP terlindungi di balik WAF.")
        print("-" * 55)