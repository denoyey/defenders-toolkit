# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import requests
from core.base_module import BaseAuditModule

class TechFingerprint(BaseAuditModule):
    @property
    def name(self) -> str:
        return "Tech Stack & WAF Fingerprinter"

    @property
    def description(self) -> str:
        return "Mendeteksi kebocoran info server (X-Powered-By) dan perlindungan WAF"

    def run(self, target: str) -> None:
        print(f"\n[*] Memulai Fingerprinting pada: {target}")
        
        try:
            response = requests.get(target, timeout=10)
            headers = response.headers
            cookies = response.cookies.get_dict()
            
            print("-" * 55)
            exposed_tech = False
            for header in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']:
                if header in headers:
                    print(f"[-] [RENTAN] Kebocoran Info! {header}: {headers[header]}")
                    exposed_tech = True
            
            if not exposed_tech:
                print("[+] [AMAN] Server tidak membocorkan versi teknologi.")

            print("-" * 55)
            
            waf_detected = False
            server_header = headers.get('Server', '').lower()
            if 'cloudflare' in server_header:
                print("[*] [INFO] Target dilindungi oleh: Cloudflare WAF")
                waf_detected = True
            elif 'awselb' in server_header or 'aws' in server_header:
                print("[*] [INFO] Target menggunakan: AWS Elastic Load Balancer / WAF")
                waf_detected = True
                
            for cookie_name in cookies.keys():
                if cookie_name.startswith('cf_') or cookie_name == '__cfduid':
                    if not waf_detected:
                        print("[*] [INFO] Target dilindungi oleh: Cloudflare WAF (terdeteksi via Cookie)")
                        waf_detected = True
                elif cookie_name.endswith('_session'):
                    print(f"[*] [INFO] Indikasi framework modern mendasari sistem (Session: {cookie_name})")

            if not waf_detected:
                print("[!] [PERINGATAN] Tidak terdeteksi adanya perlindungan WAF publik.")
            print("-" * 55)

        except requests.RequestException as e:
            print(f"[-] Gagal terhubung ke target: {e}")