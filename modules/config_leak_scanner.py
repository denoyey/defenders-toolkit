# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import requests
from core.base_module import BaseAuditModule

class ConfigLeakScanner(BaseAuditModule):
    @property
    def name(self) -> str:
        return "Database & Cache Config Leak Scanner"

    @property
    def description(self) -> str:
        return "Mencari file dump SQL, config cache, dan cadangan environment di direktori publik"

    def run(self, target: str) -> None:
        print(f"\n[*] Memulai pemindaian file konfigurasi tersembunyi pada: {target}")
        base_url = target.rstrip('/')
        
        # Payload yang menyasar semua framework dan DBMS populer
        payloads = [
            # PHP/Laravel/Symfony
            '/bootstrap/cache/config.php',
            '/config/database.php',
            
            # Node.js/React/Vue build leaks
            '/build/static/js/main.js.map', 
            '/dist/assets/index.js.map',
            
            # SQL Dumps (Sering ditinggalkan oleh admin/developer)
            '/database.sql',
            '/dump.sql',
            '/backup.sql',
            '/db.sqlite',
            '/database.sqlite',
            
            # General Editor/OS backups
            '/.env.backup',
            '/.env.swp',
            '/.DS_Store'
        ]

        found_files = []
        with requests.Session() as session:
            for payload in payloads:
                test_url = f"{base_url}{payload}"
                try:
                    response = session.get(test_url, timeout=5, allow_redirects=False)
                    
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '').lower()
                        # Pastikan bukan halaman error 404 custom yang mengembalikan status 200
                        if 'text/html' not in content_type:
                            print(f"[!] [KRITIS] File konfigurasi/DB bocor: {test_url}")
                            found_files.append(test_url)
                except requests.RequestException:
                    pass

        if not found_files:
            print("[+] Target aman dari kebocoran file database dan cache.")
        else:
            print(f"\n[*] Ditemukan {len(found_files)} celah kebocoran informasi!")