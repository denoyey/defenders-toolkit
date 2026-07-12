# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import os
import json
import glob
from abc import ABC, abstractmethod
from datetime import datetime

class BaseAuditModule(ABC):
    def __init__(self):
        self.global_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
            "Connection": "keep-alive"
        }
        self.findings = []

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @abstractmethod
    async def run(self, target: str) -> None:
        pass

    def set_auth_header(self, auth_string: str) -> None:
        if "Bearer" in auth_string or "Basic" in auth_string:
            self.global_headers["Authorization"] = auth_string
        else:
            self.global_headers["Cookie"] = auth_string

    def get_headers(self) -> dict:
        return self.global_headers

    def load_wordlist(self, filename: str) -> list:
        filepath = os.path.join(os.getcwd(), "wordlists", filename)
        if not os.path.exists(filepath):
            return []
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def add_finding(self, severity: str, title: str, details: str):
        self.findings.append({
            "severity": severity,
            "title": title,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })

    def export_report(self, target: str):
        if not self.findings:
            return None
        
        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        module_cls_name = self.__class__.__name__
        
        search_pattern = os.path.join(reports_dir, f"{domain}_{module_cls_name}_*.json")
        previous_reports = sorted(glob.glob(search_pattern))
        
        if previous_reports:
            last_report_path = previous_reports[-1]
            with open(last_report_path, "r", encoding="utf-8") as f:
                try:
                    last_data = json.load(f)
                    last_findings = last_data.get("findings", [])
                    self._print_diff(last_findings, self.findings)
                except json.JSONDecodeError:
                    pass
        else:
            print(f"\n[\033[96m*\033[0m] Baseline scan tersimpan. Tidak ada data riwayat untuk State Diffing.")

        filename = f"{domain}_{module_cls_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(reports_dir, filename)
        
        report_data = {
            "target": target,
            "module": self.name,
            "scan_time": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": self.findings
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
            
        return filepath

    def _print_diff(self, old_findings, new_findings):
        old_set = {f"{x.get('title')}::{x.get('details')}" for x in old_findings}
        new_set = {f"{x.get('title')}::{x.get('details')}" for x in new_findings}
        
        new_issues = new_set - old_set
        resolved_issues = old_set - new_set
        
        print("\n[\033[93m*\033[0m] STATE DIFFING ENGINE RESULT:")
        if not new_issues and not resolved_issues:
            print("    \033[92m└─ Tidak ada perubahan state dari scan sebelumnya. (No Alert Fatigue)\033[0m")
        
        for issue in new_issues:
            title, details = issue.split("::", 1)
            print(f"    \033[91m[+] NEW THREAT:\033[0m {title} -> {details}")
            
        for issue in resolved_issues:
            title, details = issue.split("::", 1)
            print(f"    \033[92m[-] RESOLVED:\033[0m {title} -> {details}")