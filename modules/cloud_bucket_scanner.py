# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import asyncio
import re
from core.base_module import BaseAuditModule
from core.http_client import AsyncResilientClient

class CloudBucketScanner(BaseAuditModule):
    @property
    def name(self) -> str:
        return "Cloud S3 & Subdomain Takeover Scanner"

    @property
    def description(self) -> str:
        return "Mendeteksi miskonfigurasi bucket AWS S3/GCP yang bisa diakses publik"

    async def run(self, target: str) -> None:
        print(f"\n[*] Memulai Cloud Bucket Scan pada: {target}")
        headers = self.get_headers()
        print("-" * 55)
        
        bucket_pattern = re.compile(
            r'(?:https?://)?(?:[a-zA-Z0-9_-]+\.)?(?:s3(?:-[\w-]+)?\.amazonaws\.com|storage\.googleapis\.com|[a-zA-Z0-9_-]+\.blob\.core\.windows\.net)(?:/[a-zA-Z0-9_.-]+)*'
        )

        async with AsyncResilientClient(headers=headers, limit=10, max_retries=2) as client:
            status, res_headers, text = await client.get(target)
            
            if status == 0:
                print("[-] Gagal terhubung ke target.")
                return

            buckets = set(bucket_pattern.findall(text))
            
            if not buckets:
                print("[+] Tidak ditemukan referensi Cloud Storage pihak ketiga.")
                print("-" * 55)
                return

            print(f"[*] Ditemukan {len(buckets)} referensi Cloud Storage. Menguji akses publik...")
            
            for bucket in buckets:
                if not bucket.startswith('http'):
                    bucket = f"https://{bucket}"
                    
                b_status, b_headers, b_text = await client.get(bucket)
                
                if b_status == 200 and ('<ListBucketResult' in b_text or 'xml' in b_headers.get('Content-Type', '')):
                    print(f"[!] [KRITIS] Bucket dapat dibaca secara publik: {bucket}")
                    self.add_finding("KRITIS", "Public Read Cloud Bucket", f"Bucket terekspos: {bucket}")
                elif b_status in [403, 401]:
                    print(f"[+] [AMAN] Bucket ditutup (403): {bucket}")
                elif b_status == 404:
                    print(f"[-] [PERINGATAN] Bucket tidak ditemukan (404) - Potensi Subdomain Takeover: {bucket}")
                    self.add_finding("TINGGI", "Potensi Subdomain Takeover", f"Bucket 404: {bucket}")
        
        print("-" * 55)