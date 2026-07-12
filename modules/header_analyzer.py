# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import requests
from core.base_module import BaseAuditModule

class HeaderAnalyzer(BaseAuditModule):
    @property
    def name(self) -> str:
        return "Comprehensive Security Headers Analyzer"

    @property
    def description(self) -> str:
        return "Evaluasi ketat perlindungan header HTTP standar enterprise"

    def run(self, target: str) -> None:
        print(f"\n[*] Memulai analisis Security Headers pada: {target}")
        
        security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'Anti-Clickjacking',
            'X-Content-Type-Options': 'Anti-MIME Sniffing',
            'Referrer-Policy': 'Referrer Data Protection',
            'Permissions-Policy': 'Feature Policy Control',
            'Cache-Control': 'Sensitive Data Caching'
        }

        try:
            response = requests.get(target, headers=self.get_headers(), timeout=10)
            headers = response.headers
            
            score = 0
            print("-" * 55)
            for header, desc in security_headers.items():
                if header in headers:
                    print(f"[+] [AMAN] {header} ditemukan.")
                    score += 1
                else:
                    print(f"[-] [RENTAN] {header} HILANG! ({desc})")
            print("-" * 55)
            
            print(f"[*] Skor Keamanan Header: {score}/{len(security_headers)}")
            if score < len(security_headers) // 2:
                print("[!] PERINGATAN: Konfigurasi header target tidak memenuhi standar keamanan modern.")

        except requests.RequestException:
            print("[-] Gagal terhubung ke target.")