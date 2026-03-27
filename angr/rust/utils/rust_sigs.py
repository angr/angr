from __future__ import annotations

import logging
import os
import sys

from angr.utils.env import is_pyinstaller


l = logging.getLogger(name=__name__)

def get_default_sig_dir(arch_name: str = "x86_64", platform: str = "linux") -> str | None:
    if is_pyinstaller():
        base_dir = os.path.join(os.path.dirname(sys.executable), "flirt_signatures")
    else:
        if "angrmanagement" in sys.modules:
            angrm_dir = os.path.dirname(os.path.realpath(sys.modules["angrmanagement"].__file__))
            base_dir = os.path.join(angrm_dir, "resources", "flirt_signatures")
        else:
            base_dir = None

    if base_dir is None:
        try:
            from flirt_signatures import signatures_path
            base_dir = signatures_path()
        except ImportError:
            l.warning("Could not import flirt_signatures. Please install https://github.com/angr/flirt_signatures.git in your environment.")

    if base_dir:
        sig_dir = os.path.join(base_dir, arch_name, platform, "rust")
        if os.path.isdir(sig_dir):
            return os.path.normpath(sig_dir)
    return None
