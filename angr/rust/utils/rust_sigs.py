from __future__ import annotations

import os
import sys

import angr
from angr.utils.env import is_pyinstaller


def get_default_sig_dir(arch_name: str = "x86_64", platform: str = "linux") -> str | None:
    if is_pyinstaller():  # noqa: SIM108
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.realpath(angr.__file__))

    for parent_level in range(3):
        sig_dir = os.path.join(base_dir, *[".."] * parent_level, "flirt_signatures", arch_name, platform, "rust")
        if os.path.isdir(sig_dir):
            return os.path.normpath(sig_dir)
    return None
