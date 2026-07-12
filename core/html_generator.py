# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import os
import json
from datetime import datetime

class HTMLReportGenerator:
    def __init__(self):
        self.reports_dir = os.path.join(os.getcwd(), "reports")
        self.dashboard_path = os.path.join(os.getcwd(), "dashboard.html")

    def generate(self):
        if not os.path.exists(self.reports_dir):
            return False

        all_findings = []
        total_scans = 0
        stats = {"KRITIS": 0, "TINGGI": 0, "SEDANG": 0, "INFO": 0}

        for filename in os.listdir(self.reports_dir):
            if filename.endswith(".json"):
                total_scans += 1
                filepath = os.path.join(self.reports_dir, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    try:
                        data = json.load(f)
                        module_name = data.get("module", "Unknown")
                        target = data.get("target", "Unknown")
                        for finding in data.get("findings", []):
                            sev = finding.get("severity", "INFO")
                            if sev in stats:
                                stats[sev] += 1
                            else:
                                stats["INFO"] += 1
                            
                            all_findings.append({
                                "target": target,
                                "module": module_name,
                                "severity": sev,
                                "title": finding.get("title", ""),
                                "details": finding.get("details", ""),
                                "time": finding.get("timestamp", "")
                            })
                    except Exception:
                        pass

        all_findings.sort(key=lambda x: x["time"], reverse=True)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Defenders Toolkit - Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-gray-100 font-sans p-6">
    <div class="max-w-7xl mx-auto">
        <header class="mb-8 border-b border-gray-700 pb-4">
            <h1 class="text-3xl font-bold text-cyan-400">🛡️ Defenders Toolkit Dashboard</h1>
            <p class="text-gray-400 mt-2">Enterprise Attack Surface & Vulnerability Report</p>
            <p class="text-sm text-gray-500 mt-1">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div class="bg-gray-800 p-4 rounded-lg border-l-4 border-cyan-500 shadow">
                <h2 class="text-gray-400 text-sm font-semibold">Total Scans</h2>
                <p class="text-2xl font-bold">{total_scans}</p>
            </div>
            <div class="bg-gray-800 p-4 rounded-lg border-l-4 border-red-600 shadow">
                <h2 class="text-gray-400 text-sm font-semibold">Kritis</h2>
                <p class="text-2xl font-bold text-red-500">{stats['KRITIS']}</p>
            </div>
            <div class="bg-gray-800 p-4 rounded-lg border-l-4 border-orange-500 shadow">
                <h2 class="text-gray-400 text-sm font-semibold">Tinggi</h2>
                <p class="text-2xl font-bold text-orange-400">{stats['TINGGI']}</p>
            </div>
            <div class="bg-gray-800 p-4 rounded-lg border-l-4 border-blue-500 shadow">
                <h2 class="text-gray-400 text-sm font-semibold">Info / Rendah</h2>
                <p class="text-2xl font-bold text-blue-400">{stats['INFO'] + stats['SEDANG']}</p>
            </div>
        </div>

        <div class="bg-gray-800 rounded-lg shadow overflow-hidden">
            <table class="w-full text-left border-collapse">
                <thead>
                    <tr class="bg-gray-700 text-gray-300 text-sm uppercase">
                        <th class="p-4 font-medium">Severity</th>
                        <th class="p-4 font-medium">Target</th>
                        <th class="p-4 font-medium">Module</th>
                        <th class="p-4 font-medium">Title</th>
                        <th class="p-4 font-medium">Details</th>
                        <th class="p-4 font-medium">Time</th>
                    </tr>
                </thead>
                <tbody class="text-sm">
"""
        for f in all_findings:
            sev_color = "bg-gray-600"
            if f['severity'] == "KRITIS": sev_color = "bg-red-600 text-white font-bold"
            elif f['severity'] == "TINGGI": sev_color = "bg-orange-500 text-white font-bold"
            elif f['severity'] == "INFO": sev_color = "bg-blue-500 text-white"

            html_content += f"""
                    <tr class="border-b border-gray-700 hover:bg-gray-700 transition duration-150">
                        <td class="p-4"><span class="px-2 py-1 rounded text-xs {sev_color}">{f['severity']}</span></td>
                        <td class="p-4 text-cyan-300">{f['target']}</td>
                        <td class="p-4 text-gray-400">{f['module']}</td>
                        <td class="p-4 font-semibold text-white">{f['title']}</td>
                        <td class="p-4 break-all text-gray-400 text-xs">{f['details']}</td>
                        <td class="p-4 text-gray-500 text-xs whitespace-nowrap">{f['time'][:19].replace('T', ' ')}</td>
                    </tr>
"""

        html_content += """
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
        with open(self.dashboard_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return self.dashboard_path