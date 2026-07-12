# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import requests
import base64
import json
import re
from core.base_module import BaseAuditModule

class JWTInspector(BaseAuditModule):
    @property
    def name(self) -> str:
        return "JWT (JSON Web Token) Security Inspector"

    @property
    def description(self) -> str:
        return "Mendeteksi penggunaan JWT yang lemah dan mendekode payload-nya"

    def run(self, target: str) -> None:
        print(f"\n[*] Memulai inspeksi JWT pada: {target}")
        
        try:
            response = requests.get(target, timeout=10)
            jwt_found = []
            
            # 1. Mencari JWT di dalam Cookies
            for name, value in response.cookies.items():
                if self._is_jwt(value):
                    jwt_found.append((name, value))
                    
            # 2. Mencari JWT di dalam Response Body (menggunakan regex)
            jwt_pattern = re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*')
            for match in jwt_pattern.findall(response.text):
                # Hindari duplikasi jika JWT di response body sama dengan di cookie
                if not any(match in j for j in jwt_found):
                     jwt_found.append(("Body/Header", match))

            print("-" * 55)
            if not jwt_found:
                print("[+] [INFO] Tidak ditemukan pola JWT pada target.")
                print("-" * 55)
                return

            print(f"[!] Ditemukan {len(jwt_found)} indikasi JWT.")
            for source, token in jwt_found:
                print(f"\n[*] Menganalisis JWT dari: {source}")
                self._analyze_jwt(token)
                
            print("-" * 55)

        except requests.RequestException as e:
            print(f"[-] Gagal terhubung ke target: {e}")

    def _is_jwt(self, token: str) -> bool:
        """Memeriksa apakah string merupakan format JWT"""
        parts = token.split('.')
        return len(parts) == 3 and parts[0].startswith('eyJ')

    def _analyze_jwt(self, token: str):
        """Mendekode dan mengevaluasi isi JWT"""
        parts = token.split('.')
        try:
            # Decode Header
            header_padded = parts[0] + '=' * (-len(parts[0]) % 4)
            header_json = base64.b64decode(header_padded).decode('utf-8')
            header = json.loads(header_json)
            
            # Decode Payload
            payload_padded = parts[1] + '=' * (-len(parts[1]) % 4)
            payload_json = base64.b64decode(payload_padded).decode('utf-8')
            payload = json.loads(payload_json)

            print(f"    [+] Algoritma (Header): {header.get('alg', 'Unknown')}")
            if header.get('alg') == 'none':
                print("        [!] KRITIS: Algoritma 'none' diizinkan. Token bisa dipalsukan!")
                
            print(f"    [+] Payload Data:")
            for key, value in payload.items():
                print(f"        - {key}: {value}")
                
            # Mengecek apakah ada indikasi data sensitif di payload
            sensitive_keys = ['password', 'secret', 'key', 'pin', 'ssn', 'credit_card']
            for s_key in sensitive_keys:
                if any(s_key in k.lower() for k in payload.keys()):
                     print(f"        [!] PERINGATAN: Potensi kebocoran data sensitif pada key '{s_key}'!")

        except Exception as e:
            print(f"    [-] Gagal mendekode token (mungkin bukan JWT yang valid): {e}")