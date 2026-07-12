# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import requests
from urllib.parse import urlparse, urljoin
import re
from core.base_module import BaseAuditModule

class OpenRedirectScanner(BaseAuditModule):
    @property
    def name(self) -> str:
        return "Advanced Open Redirect Scanner"

    @property
    def description(self) -> str:
        return "Pemindaian komprehensif Open Redirect dengan teknik bypass WAF/Filter"

    def run(self, target: str) -> None:
        print(f"\n[*] Memulai Advanced Open Redirect Scanning pada: {target}")
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if not base_url.endswith('/'):
            base_url += '/'
            
        endpoints = ['', 'login', 'auth', 'signin', 'logout', 'redirect']
        
        params = [
            'next', 'url', 'redirect', 'return', 'redirect_uri', 
            'continue', 'go', 'out', 'view', 'dir', 'path', 
            'dest', 'file', 'jump', 'to', 'target', 'r', 'link', 'page'
        ]
        
        payloads = [
            "https://www.google.com",
            "//www.google.com",
            "/\\www.google.com",
            "https:www.google.com",
            "%2F%2Fwww.google.com"
        ]
        
        print("-" * 55)
        found_vuln = False
        
        with requests.Session() as session:
            for endpoint in endpoints:
                target_url = urljoin(base_url, endpoint)
                for param in params:
                    for payload in payloads:
                        test_url = f"{target_url}?{param}={payload}"
                        
                        try:
                            response = session.get(test_url, timeout=5, allow_redirects=False)
                            
                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                if 'google.com' in location:
                                    print(f"[!] [KRITIS] Terdeteksi pada: {test_url}")
                                    print(f"    ├─ Payload Bypass: {payload}")
                                    print(f"    └─ Dialihkan ke: {location}\n")
                                    found_vuln = True
                                    
                            elif response.status_code == 200:
                                meta_pattern = r'(?i)<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\d+;\s*url=.*google\.com'
                                if re.search(meta_pattern, response.text):
                                    print(f"[!] [KRITIS] HTML Meta-Refresh Redirect terdeteksi: {test_url}")
                                    print(f"    ├─ Payload Bypass: {payload}")
                                    print(f"    └─ Eksekusi via DOM/HTML tag\n")
                                    found_vuln = True
                                    
                        except requests.RequestException:
                            pass

        if not found_vuln:
            print("[+] [AMAN] Tidak ditemukan celah Open Redirect dengan teknik bypass.")
        print("-" * 55)