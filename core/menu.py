# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import os
import sys
import asyncio
from datetime import datetime
from modules.sensitive_scanner import SensitiveFileScanner
from modules.graphql_scanner import GraphQLScanner
from modules.cloud_bucket_scanner import CloudBucketScanner
from modules.subdomain_enum import SubdomainEnumerator
from modules.js_secrets_scanner import JSSecretsScanner
from modules.sbom_cve_analyzer import SBOMCVEAnalyzer
from modules.waf_origin_discovery import WAFOriginDiscovery
from core.html_generator import HTMLReportGenerator

class Color:
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class CLIMenu:
    def __init__(self):
        self.modules = [
            SubdomainEnumerator(),
            WAFOriginDiscovery(),
            SensitiveFileScanner(),
            GraphQLScanner(),
            CloudBucketScanner(),
            JSSecretsScanner(),
            SBOMCVEAnalyzer()
        ]
        self.current_auth = "None"
        self.html_gen = HTMLReportGenerator()

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def display_banner(self):
        self.clear_screen()
        current_year = datetime.now().year
        
        banner = f"""
{Color.BLUE}{Color.BOLD}
 ██████╗ ███████╗███████╗███████╗███╗   ██╗██████╗ ███████╗██████╗ 
 ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗
 ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║██║  ██║█████╗  ██████╔╝
 ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
 ██████╔╝███████╗██║     ███████╗██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
{Color.CYAN}       [ Blue Team Security Auditing Toolkit - Enterprise ]{Color.RESET}
{Color.YELLOW}              - github.com/denoyey | (c) {current_year} {Color.RESET} -
        """
        print(banner)
        print(f"{Color.GREEN}       [+] Active Authentication: {self.current_auth}{Color.RESET}\n")

    def display_main_menu(self):
        self.display_banner()
        print(f"{Color.CYAN}" + "="*70 + f"{Color.RESET}")
        print(f"{Color.BOLD} SELECT MODULE ATAU ACTION:{Color.RESET}")
        print(f"{Color.CYAN}" + "="*70 + f"{Color.RESET}\n")
        
        for idx, module in enumerate(self.modules, 1):
            print(f"  {Color.GREEN}[{idx}]{Color.RESET} {Color.BOLD}{module.name}{Color.RESET}")
            print(f"      {Color.BLUE}└─{Color.RESET} {module.description}")
            
        print(f"\n  {Color.YELLOW}[A]{Color.RESET} {Color.BOLD}Set Global Authentication (Bearer/Cookie){Color.RESET}")
        print(f"  {Color.CYAN}[R]{Color.RESET} {Color.BOLD}Generate HTML Dashboard (Build Report){Color.RESET}")
        print(f"  {Color.RED}[0]{Color.RESET} {Color.BOLD}Exit Toolkit{Color.RESET}")
        print(f"\n{Color.CYAN}" + "="*70 + f"{Color.RESET}")

    def prompt(self):
        while True:
            try:
                self.display_main_menu()
                choice = input(f"\n{Color.BOLD}🛡️  DEFENDER > {Color.RESET}").strip().upper()
                
                if choice == '0':
                    print(f"\n{Color.GREEN}[*] Exiting toolkit. Keep your systems safe, Deni!{Color.RESET}")
                    break
                    
                if choice == 'A':
                    auth_input = input(f"\n{Color.YELLOW}[?] Masukkan Bearer Token atau string Cookie: {Color.RESET}").strip()
                    if auth_input:
                        self.current_auth = "Set (Hidden for Security)"
                        for module in self.modules:
                            module.set_auth_header(auth_input)
                    continue
                    
                if choice == 'R':
                    print(f"\n{Color.CYAN}[*] Merender HTML Dashboard...{Color.RESET}")
                    res = self.html_gen.generate()
                    if res:
                        print(f"{Color.GREEN}[+] Berhasil! Buka file ini di browser Anda:{Color.RESET}")
                        print(f"    └─ file://{res}")
                    else:
                        print(f"{Color.RED}[-] Folder reports kosong atau tidak ditemukan.{Color.RESET}")
                    input(f"\n{Color.BLUE}[*] Tekan Enter untuk melanjutkan...{Color.RESET}")
                    continue

                try:
                    idx = int(choice) - 1
                except ValueError:
                    print(f"\n{Color.RED}[-] Masukkan perintah yang valid.{Color.RESET}")
                    input(f"{Color.BLUE}[*] Tekan Enter untuk melanjutkan...{Color.RESET}")
                    continue

                if 0 <= idx < len(self.modules):
                    module = self.modules[idx]
                    
                    while True:
                        self.display_banner()
                        print(f"{Color.CYAN}" + "="*70 + f"{Color.RESET}")
                        print(f"{Color.BOLD} 🎯 SELECTED MODULE: {module.name}{Color.RESET}")
                        print(f"    {Color.BLUE}└─ {module.description}{Color.RESET}")
                        print(f"{Color.CYAN}" + "="*70 + f"{Color.RESET}\n")
                        print(f"  {Color.RED}[0]{Color.RESET} {Color.BOLD}Kembali ke Menu Utama{Color.RESET}\n")
                        
                        target = input(f"{Color.YELLOW}[?] Masukkan Target URL/Domain: {Color.RESET}").strip()
                        
                        if target == '0':
                            break 
                            
                        if not target.startswith('http') and idx != 0:
                            print(f"\n{Color.RED}[-] Format URL tidak valid. Harus diawali http:// atau https://{Color.RESET}")
                            input(f"{Color.BLUE}[*] Tekan Enter untuk mengulangi...{Color.RESET}")
                            continue
                        
                        self.display_banner()
                        print(f"{Color.CYAN}[*] Executing {module.name} pada {target}...{Color.RESET}\n")
                        
                        module.findings = []
                        asyncio.run(module.run(target))
                        
                        report_path = module.export_report(target)
                        if report_path:
                            print(f"\n{Color.GREEN}[+] Report JSON berhasil disimpan di:{Color.RESET}")
                            print(f"    └─ {report_path}")
                        
                        input(f"\n{Color.BLUE}[*] Tekan Enter untuk kembali ke menu utama...{Color.RESET}")
                        break 
                        
                else:
                    print(f"\n{Color.RED}[-] Pilihan tidak valid.{Color.RESET}")
                    input(f"{Color.BLUE}[*] Tekan Enter untuk melanjutkan...{Color.RESET}")
            
            except KeyboardInterrupt:
                print(f"\n\n{Color.GREEN}[*] Force exit detected (Ctrl+C). Exiting toolkit. Stay safe, Deni!{Color.RESET}")
                sys.exit(0)