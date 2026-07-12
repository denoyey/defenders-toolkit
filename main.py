# ==========================================
# Copyright (c) 2026 Defenders Toolkit
# All Rights Reserved.
# ==========================================
from core.setup import Installer
from core.menu import CLIMenu

if __name__ == "__main__":
    Installer.check_and_install()
    
    app = CLIMenu()
    app.prompt()