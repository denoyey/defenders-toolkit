# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import requests
# pyrefly: ignore [missing-import]
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from core.base_module import BaseAuditModule

class FormAnalyzer(BaseAuditModule):
    @property
    def name(self) -> str:
        return "Advanced Form Security & CSRF Analyzer"

    @property
    def description(self) -> str:
        return "Analisis form untuk CSRF, unencrypted submit, dan external hijacking"

    def run(self, target: str) -> None:
        print(f"\n[*] Memulai Advanced Form Analysis pada: {target}")
        try:
            response = requests.get(target, headers=self.get_headers(), timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                print("[!] Tidak ada form HTML statis ditemukan pada target.")
                return

            target_domain = urlparse(target).netloc
            print(f"[+] Ditemukan {len(forms)} form.\n")

            for idx, form in enumerate(forms, 1):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                print(f"  [{idx}] Action: {action or 'Self (Current URL)'} | Method: {method}")
                
                action_domain = urlparse(action).netloc
                if action_domain and action_domain != target_domain:
                    print(f"      [!] [PERINGATAN] Form mengirim data ke domain eksternal: {action_domain}")
                    
                if action.startswith('http://'):
                    print("      [!] [KRITIS] Pengiriman data tanpa enkripsi (HTTP)")

                if method == 'POST':
                    csrf_found = False
                    inputs = form.find_all('input')
                    for inp in inputs:
                        name = inp.get('name', '').lower()
                        if any(x in name for x in ['csrf', 'token', '_token', 'xsrf']):
                            csrf_found = True
                            break
                    if not csrf_found:
                        print("      [-] [RENTAN] Form POST tidak memiliki token Anti-CSRF statis")
                        
        except requests.RequestException:
            print("[-] Gagal terhubung ke target.")