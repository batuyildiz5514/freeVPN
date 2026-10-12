"""PyVPN Main Application Launcher.

Launches the modern desktop GUI with automated Administrator UAC elevation.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.wintun import is_admin, request_admin_elevation
from ui.app import main

if __name__ == "__main__":
    if "--no-elevate" not in sys.argv and not is_admin():
        print("[*] PyVPN requires Administrator privileges for network driver access.")
        try:
            request_admin_elevation()
        except Exception:
            pass  # Fallback to standard launch if cancelled
    main()
