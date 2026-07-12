import asyncio
from bs4 import BeautifulSoup
from core.base_module import BaseAuditModule
from core.http_client import AsyncResilientClient

class TechFingerprint(BaseAuditModule):
    @property
    def name(self) -> str:
        return "Tech Stack & WAF Fingerprinter (Async)"

    @property
    def description(self) -> str:
        return "Mendeteksi WAF, kebocoran info server, dan footprint framework"

    async def run(self, target: str) -> None:
        print(f"\n[*] Memulai Fingerprinting pada: {target}")
        base_url = target if target.endswith('/') else f"{target}/"
        headers = self.get_headers()
        
        technologies = set()
        exposed_tech = False
        waf_detected = False
        
        async with AsyncResilientClient(headers=headers, limit=5, max_retries=2) as client:
            status, res_headers, text = await client.get(base_url)
            
            if status == 0:
                print("[-] Gagal terhubung ke target.")
                print("-" * 55)
                return

            print("-" * 55)
            
            for header in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']:
                for res_header_key in res_headers.keys():
                    if header.lower() == res_header_key.lower():
                        val = res_headers[res_header_key]
                        print(f"[-] [\033[91mRENTAN\033[0m] Kebocoran Info! {header}: {val}")
                        self.add_finding("TINGGI", f"Info Leak: {header}", f"Server membocorkan: {val}")
                        technologies.add(f"Header Leak: {header} ({val})")
                        exposed_tech = True
            
            if not exposed_tech:
                print("[+] [AMAN] Server tidak membocorkan versi teknologi dari HTTP Headers.")

            print("-" * 55)
            
            server_header = res_headers.get('Server', '').lower()
            if 'cloudflare' in server_header:
                print("[*] [INFO] Target dilindungi oleh: Cloudflare WAF")
                technologies.add("WAF: Cloudflare")
                waf_detected = True
            elif 'awselb' in server_header or 'aws' in server_header:
                print("[*] [INFO] Target menggunakan: AWS Elastic Load Balancer / WAF")
                technologies.add("WAF: AWS ELB/WAF")
                waf_detected = True

            cookies = res_headers.get('Set-Cookie', '')
            if 'cf_' in cookies.lower() or '__cfduid' in cookies.lower():
                if not waf_detected:
                    print("[*] [INFO] Target dilindungi oleh: Cloudflare WAF (terdeteksi via Cookie)")
                    technologies.add("WAF: Cloudflare (Cookie)")
                    waf_detected = True
            
            if 'laravel_session' in cookies or 'XSRF-TOKEN' in cookies:
                technologies.add("Framework: Laravel")
            if 'PHPSESSID' in cookies:
                technologies.add("Language: PHP")
            if 'JSESSIONID' in cookies:
                technologies.add("Language: Java")
            if 'csrftoken' in cookies:
                technologies.add("Framework: Django")

            if text:
                soup = BeautifulSoup(text, 'html.parser')
                
                if soup.find(id='__next'):
                    technologies.add("Frontend: Next.js (React)")
                if soup.find(id='__nuxt'):
                    technologies.add("Frontend: Nuxt.js (Vue)")
                if soup.find(attrs={"data-reactroot": True}):
                    technologies.add("Frontend: React")
                if 'wp-content/' in text:
                    technologies.add("CMS: WordPress")
                if 'livewire' in text.lower():
                    technologies.add("Frontend: Laravel Livewire")
                if 'filament' in text.lower():
                    technologies.add("Admin Panel: Laravel Filament")
                if 'tailwindcss' in text.lower() or 'tailwind' in text.lower():
                    technologies.add("CSS: Tailwind CSS")

            if not waf_detected:
                print("[!] [\033[93mPERINGATAN\033[0m] Tidak terdeteksi adanya perlindungan WAF publik.")
                self.add_finding("SEDANG", "Missing WAF", "Tidak terdeteksi WAF (Cloudflare/AWS) pada target")

            print("-" * 55)
            
            if technologies:
                print(f"[*] Ditemukan {len(technologies)} indikator teknologi/arsitektur:\n")
                for tech in sorted(technologies):
                    print(f"    \033[92m└─\033[0m {tech}")
            
        print("-" * 55)