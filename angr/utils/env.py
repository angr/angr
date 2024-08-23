from __future__ import annotations
import sys


def is_pyinstaller() -> bool:
    """
    Detect if we are currently running as a PyInstaller-packaged program.

    :return:    True if we are running as a PyInstaller-packaged program. False if we are running in Python directly
                (e.g., development mode).
    """
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")
