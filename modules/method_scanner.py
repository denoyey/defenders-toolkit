# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import requests
from core.base_module import BaseAuditModule

class MethodScanner(BaseAuditModule):
    @property
    def name(self) -> str:
        return "Dangerous HTTP Methods Scanner"

    @property
    def description(self) -> str:
        return "Menguji metode HTTP berbahaya yang terbuka (TRACE, PUT, DELETE)"

    def run(self, target: str) -> None:
        print(f"\n[*] Memulai HTTP Method Scanning pada: {target}")
        
        methods = {
            'TRACE': 'Rentan terhadap Cross-Site Tracing (XST)',
            'TRACK': 'Rentan terhadap Cross-Site Tracing (XST)',
            'PUT': 'Potensi modifikasi/unggah file tanpa izin',
            'DELETE': 'Potensi penghapusan data tanpa izin'
        }

        try:
            print("-" * 55)
            options_res = requests.options(target, timeout=10)
            allowed_methods = options_res.headers.get('Allow', 'Tidak Dideklarasikan')
            print(f"[*] Server Allow Header: {allowed_methods}")
            print("-" * 55)

            for method, risk in methods.items():
                try:
                    res = requests.request(method, target, timeout=5)
                    
                    if res.status_code == 200:
                        print(f"[!] [KRITIS] Metode {method} TERBUKA! ({risk})")
                        if method == 'TRACE' and 'TRACE /' in res.text:
                            print(f"    └─ [EKSPLOIT] Server memantulkan input! Celah XST Valid!")
                    elif res.status_code in [405, 403, 501]:
                        print(f"[+] [AMAN] Metode {method} ditolak (Status {res.status_code}).")
                    else:
                        print(f"[?] [INFO] Metode {method} merespons dengan status {res.status_code}.")
                except requests.RequestException:
                    print(f"[-] Gagal menguji metode {method} (Timeout/Error).")
            
            print("-" * 55)

        except requests.RequestException as e:
            print(f"[-] Gagal terhubung ke target: {e}")