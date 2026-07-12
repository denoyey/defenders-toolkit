# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import requests
from core.base_module import BaseAuditModule

class CORSAnalyzer(BaseAuditModule):
    @property
    def name(self) -> str:
        return "CORS Misconfiguration Analyzer"

    @property
    def description(self) -> str:
        return "Menguji kelemahan Cross-Origin Resource Sharing (CORS)"

    def run(self, target: str) -> None:
        print(f"\n[*] Memulai analisis CORS pada: {target}")
        test_origin = "https://evil-domain.com"
        headers = {'Origin': test_origin}

        try:
            response = requests.options(target, headers=headers, timeout=10)
            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')

            print("-" * 55)
            if not acao:
                print("[+] [AMAN] CORS Header tidak ditemukan (Akses pihak ketiga ditolak).")
            elif acao == "*":
                print("[-] [PERINGATAN] Akses terbuka untuk semua domain (Wildcard '*').")
                if acac == "true":
                    print("[!] [KRITIS] Wildcard dengan Allow-Credentials=true (Sangat Rentan!).")
            elif acao == test_origin:
                print(f"[!] [KRITIS] Server memantulkan Origin jahat (Reflection)!")
            else:
                print(f"[+] [INFO] CORS diizinkan secara spesifik untuk: {acao}")
            print("-" * 55)

        except requests.RequestException as e:
            print(f"[-] Gagal terhubung ke target: {e}")