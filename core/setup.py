# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
import subprocess
import sys

class Installer:
    @staticmethod
    def check_and_install():
        print("[*] Memeriksa dependensi sistem...")
        try:
            import requests
            import bs4
            print("[+] Dependensi utama sudah terinstal dengan baik.\n")
        except ImportError:
            print("[-] Beberapa dependensi hilang. Menginstal otomatis...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
                print("[+] Instalasi selesai.\n")
            except Exception as e:
                print(f"[-] Gagal menginstal dependensi: {e}")
                sys.exit(1)