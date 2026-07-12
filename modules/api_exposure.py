# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import requests
from core.base_module import BaseAuditModule

class APIExposureScanner(BaseAuditModule):
    @property
    def name(self) -> str:
        return "Dev Tools & API Exposure Scanner"

    @property
    def description(self) -> str:
        return "Mendeteksi panel debug dan dokumentasi API yang terekspos"

    def run(self, target: str) -> None:
        print(f"\n[*] Memulai pemindaian API/Dev Exposure pada: {target}")
        base_url = target.rstrip('/')
        
        endpoints = [
            '/swagger-ui.html', '/api/docs', '/openapi.json',
            '/telescope', '/horizon', '/graphql'
        ]

        found = False
        with requests.Session() as session:
            for endpoint in endpoints:
                url = f"{base_url}{endpoint}"
                try:
                    response = session.get(url, timeout=5, allow_redirects=False)
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '').lower()
                        if 'json' in content_type or 'html' in content_type:
                            print(f"[!] [KRITIS] Endpoint API/Debug terekspos: {url}")
                            found = True
                except requests.RequestException:
                    continue

        if not found:
            print("[+] Target aman dari eksposur dokumentasi API dan panel Debug.")