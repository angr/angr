from __future__ import annotations

import logging
import os
import shutil
import tarfile
import tempfile
import urllib.request

from platformdirs import user_cache_dir


l = logging.getLogger(name=__name__)


TARBALL_URL = "https://github.com/angr/flirt_signatures/archive/refs/heads/master.tar.gz"
SENTINEL_FILENAME = ".download_complete"


def _download_flirt_signatures(target_dir: str) -> bool:
    """
    Download the flirt_signatures master tarball from GitHub and extract it into target_dir.
    The tarball's top-level ``flirt_signatures-master/`` wrapper is flattened so the resulting
    layout is ``<target_dir>/<arch>/<platform>/…``.

    Returns True on success, False on any failure (network, HTTP, extraction).
    """
    parent = os.path.dirname(target_dir) or "."
    os.makedirs(parent, exist_ok=True)
    staging = tempfile.mkdtemp(prefix="flirt_signatures-", dir=parent)
    try:
        with urllib.request.urlopen(TARBALL_URL) as resp, tarfile.open(fileobj=resp, mode="r|gz") as tar:
            tar.extractall(staging)

        entries = os.listdir(staging)
        if len(entries) == 1 and os.path.isdir(os.path.join(staging, entries[0])):
            extracted_root = os.path.join(staging, entries[0])
        else:
            extracted_root = staging

        with open(os.path.join(extracted_root, SENTINEL_FILENAME), "w", encoding="utf-8"):
            pass

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


def get_default_sig_dir(arch_name: str = "x86_64", platform: str = "linux") -> str | None:
    base_dir = os.path.join(user_cache_dir("angr"), "flirt_signatures")
    if not os.path.isfile(os.path.join(base_dir, SENTINEL_FILENAME)) and not _download_flirt_signatures(base_dir):
        return None

    sig_dir = os.path.join(base_dir, arch_name, platform, "rust")
    if os.path.isdir(sig_dir):
        return os.path.normpath(sig_dir)
    return None
