# Defenders Toolkit

**Blue Team Security Auditing Toolkit - Enterprise**

Defenders Toolkit is a comprehensive and asynchronous security auditing framework built in Python. Designed for Blue Teams and security professionals, it automates the discovery of common web vulnerabilities, misconfigurations, and sensitive data exposures.

## 🚀 Features

- **Asynchronous Execution:** Built on top of `asyncio` and `aiohttp` for lightning-fast and non-blocking security checks.
- **Modular Architecture:** Easily extensible with various scanning modules.
- **Interactive CLI:** A user-friendly, color-coded Command Line Interface.
- **HTML Dashboard Reporting:** Automatically generates beautiful HTML reports for your findings.
- **Global Authentication:** Supports injecting Bearer tokens or Cookie strings globally across all modules for authenticated testing.

## 🧩 Included Modules

The toolkit currently exposes the following core modules through its CLI:

- **OSINT Subdomain Enumerator**
  Extracts subdomains from Certificate Transparency logs (`crt.sh`) for attack surface mapping.
- **Enterprise Sensitive Exposure Scanner**
  Performs asynchronous scanning using dynamic wordlists, anti-WAF mechanisms, and JSON reporting to find exposed sensitive files.
- **GraphQL Introspection Scanner**
  Detects GraphQL endpoints and tests for schema leakage via Introspection queries.
- **Cloud S3 & Subdomain Takeover Scanner**
  Identifies misconfigured AWS S3 and GCP buckets that are publicly accessible.

*(Note: The `modules/` directory contains many other scanners like JWT inspector, CORS analyzer, Config leak scanner, etc., which can be integrated as needed.)*

## 🛠️ Installation

Ensure you have **Python 3.8+** installed.

```bash
git clone https://github.com/denoyey/defenders-toolkit.git
cd defenders-toolkit
# Opsional: Buat virtual environment
python3 -m venv venv
source venv/bin/activate
```

*Defenders Toolkit will automatically verify and install the required dependencies (from `requirements.txt`) upon its first run.*

## 💻 Usage

Start the interactive toolkit by running:

```bash
python3 main.py
```

Once the CLI is running, you can:
1. **Select a module** by entering its corresponding number.
2. **Input your target** URL or domain when prompted.
3. Use the `[A]` option to set a global **Bearer Token or Cookie** if the target requires authentication.
4. Use the `[R]` option to generate a beautiful **HTML Dashboard** compiling all your scan reports.

## ⚠️ Disclaimer

This toolkit is developed for educational and professional security auditing purposes only. **Ensure you have explicit permission** to test the target systems before running any scans. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---
**Copyright (c) 2026 Defenders Toolkit**
**All Rights Reserved.**
