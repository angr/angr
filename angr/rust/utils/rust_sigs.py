from __future__ import annotations

import logging
import os
import shutil
import sys
import tarfile
import tempfile
import urllib.request

from platformdirs import user_cache_dir

from angr.utils.env import is_pyinstaller


l = logging.getLogger(name=__name__)


TARBALL_URL = "https://github.com/angr/flirt_signatures/archive/refs/heads/master.tar.gz"
SENTINEL_FILENAME = ".download_complete"


def _download_flirt_signatures(target_dir: str) -> bool:
    """
    Download the flirt_signatures master tarball from GitHub and extract it into target_dir.
    The tarball's top-level ``flirt_signatures-master/`` wrapper is flattened so the layout
    matches the PyInstaller/angrmanagement bundles (``<target_dir>/<arch>/<platform>/…``).

    Returns True on success, False on any failure (network, HTTP, extraction).
    """
    parent = os.path.dirname(target_dir) or "."
    os.makedirs(parent, exist_ok=True)
    staging = tempfile.mkdtemp(prefix="flirt_signatures-", dir=parent)
    try:
        with urllib.request.urlopen(TARBALL_URL) as resp:
            with tarfile.open(fileobj=resp, mode="r|gz") as tar:
                tar.extractall(staging)

        entries = os.listdir(staging)
        if len(entries) == 1 and os.path.isdir(os.path.join(staging, entries[0])):
            extracted_root = os.path.join(staging, entries[0])
        else:
            extracted_root = staging

        open(os.path.join(extracted_root, SENTINEL_FILENAME), "w").close()

        if os.path.isdir(target_dir):
            shutil.rmtree(target_dir)
        os.replace(extracted_root, target_dir)
    except Exception as e:  # pylint:disable=broad-exception-caught
        l.warning("Failed to download FLIRT signatures from %s: %s", TARBALL_URL, e)
        shutil.rmtree(staging, ignore_errors=True)
        return False
    else:
        return True
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _resolve_base_dir() -> str | None:
    if is_pyinstaller():
        return os.path.join(os.path.dirname(sys.executable), "flirt_signatures")

    if "angrmanagement" in sys.modules:
        angrm_file = sys.modules["angrmanagement"].__file__
        assert angrm_file is not None
        angrm_dir = os.path.dirname(os.path.realpath(angrm_file))
        return os.path.join(angrm_dir, "resources", "flirt_signatures")

    cache_dir = os.path.join(user_cache_dir("angr"), "flirt_signatures")
    if os.path.isfile(os.path.join(cache_dir, SENTINEL_FILENAME)):
        return cache_dir

    if _download_flirt_signatures(cache_dir):
        return cache_dir

    return None


def get_default_sig_dir(arch_name: str = "x86_64", platform: str = "linux") -> str | None:
    base_dir = _resolve_base_dir()
    if base_dir:
        sig_dir = os.path.join(base_dir, arch_name, platform, "rust")
        if os.path.isdir(sig_dir):
            return os.path.normpath(sig_dir)
    return None