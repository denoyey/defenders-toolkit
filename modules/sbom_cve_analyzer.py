# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import asyncio
import json
import re
from core.base_module import BaseAuditModule
from core.http_client import AsyncResilientClient

class SBOMCVEAnalyzer(BaseAuditModule):
    @property
    def name(self) -> str:
        return "SBOM & CVE Analyzer"

    @property
    def description(self) -> str:
        return "Mengekstrak package.json dan memvalidasi komponen terhadap OSV API"

    async def run(self, target: str) -> None:
        print(f"\n[*] Memulai SBOM & CVE Analysis pada: {target}")
        base_url = target if target.endswith('/') else f"{target}/"
        headers = self.get_headers()
        package_url = f"{base_url}package.json"
        
        print("-" * 55)
        
        async with AsyncResilientClient(headers=headers, limit=20, max_retries=2) as client:
            status, res_headers, text = await client.get(package_url)
            
            if status != 200:
                print(f"[-] File package.json tidak ditemukan atau tertutup di {package_url}")
                print("-" * 55)
                return
                
            try:
                data = json.loads(text)
            except ValueError:
                print("[-] Target mengembalikan respons sukses, tetapi bukan format JSON valid.")
                print("-" * 55)
                return
                
            dependencies = data.get("dependencies", {})
            dev_dependencies = data.get("devDependencies", {})
            all_deps = {**dependencies, **dev_dependencies}
            
            if not all_deps:
                print("[+] package.json ditemukan tetapi tidak mengandung deklarasi dependensi.")
                print("-" * 55)
                return

            print(f"[*] Mengekstrak {len(all_deps)} dependensi NPM. Memvalidasi CVE via OSV API...")
            
            async def check_cve(pkg_name, pkg_version):
                raw_version = pkg_version.split(' ')[0]
                clean_version = re.sub(r'[\^~>=<]', '', raw_version).strip()
                
                if not clean_version or clean_version == '*' or clean_version == 'latest':
                    return

                payload = {
                    "version": clean_version,
                    "package": {
                        "name": pkg_name,
                        "ecosystem": "npm"
                    }
                }
                
                try:
                    async with client.session.post("https://api.osv.dev/v1/query", json=payload, timeout=10) as osv_res:
                        if osv_res.status == 200:
                            osv_data = await osv_res.json()
                            vulns = osv_data.get("vulns", [])
                            if vulns:
                                print(f"[!] [KRITIS] {pkg_name}@{clean_version} rentan! ({len(vulns)} CVE)")
                                for vuln in vulns:
                                    vuln_id = vuln.get("id", "Unknown_CVE")
                                    aliases = ", ".join(vuln.get("aliases", []))
                                    print(f"    ├─ Vulnerability ID: {vuln_id}")
                                    self.add_finding(
                                        "KRITIS", 
                                        f"Vulnerable Component: {pkg_name}", 
                                        f"Version: {clean_version} terjangkit {vuln_id} ({aliases})"
                                    )
                except Exception:
                    pass

            tasks = [check_cve(pkg, ver) for pkg, ver in all_deps.items()]
            await asyncio.gather(*tasks)

        if not self.findings:
            print("[+] Seluruh komponen aplikasi aman dari CVE publik yang tercatat.")
        print("-" * 55)