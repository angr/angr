# This submodule stores and manages FLIRT signatures

from typing import Set, List, Dict, Optional
import os
import json
from collections import defaultdict
import logging

import nampa

_l = logging.getLogger(__name__)


class FlirtSignature:
    """
    This class describes a FLIRT signature.
    """

    def __init__(
        self,
        arch: str,
        platform: str,
        sig_name: str,
        sig_path: str,
        unique_strings: set[str] | None = None,
        compiler: str | None = None,
        compiler_version: str | None = None,
        os_name: str | None = None,
        os_version: str | None = None,
    ):
        self.arch = arch
        self.platform = platform
        self.sig_name = sig_name
        self.sig_path = sig_path
        self.unique_strings = unique_strings
        self.compiler = compiler
        self.compiler_version = compiler_version
        self.os_name = os_name
        self.os_version = os_version

    def __repr__(self):
        if self.os_name:
            if self.os_version:
                return f"<{self.sig_name}@{self.arch}-{self.os_name}-{self.os_version}>"
            return f"<{self.sig_name}@{self.arch}-{self.os_name}>"
        return f"<{self.sig_name}@{self.arch}-{self.platform}>"


FS = FlirtSignature

# A dict from architecture names to FLIRT signatures under that architecture. Arch names are always in lower case.
FLIRT_SIGNATURES_BY_ARCH: dict[str, list[FlirtSignature]] = defaultdict(list)
LIBRARY_TO_SIGNATURES: dict[str, list[FlirtSignature]] = defaultdict(list)
STRING_TO_LIBRARIES: dict[str, set[str]] = defaultdict(set)


def load_signatures(path: str) -> None:
    """
    Recursively load all FLIRT signatures under a specific path.

    :param path:    Location of FLIRT signatures.
    """

    FLIRT_SIGNATURES_BY_ARCH.clear()
    LIBRARY_TO_SIGNATURES.clear()
    STRING_TO_LIBRARIES.clear()

    for root, _, filenames in os.walk(path):
        for filename in filenames:
            if filename.endswith(".sig"):
                # parse it
                sig_path = os.path.join(root, filename)
                try:
                    with open(sig_path, "rb") as f:
                        flirt_header = nampa.flirt.parse_header(f)
                except nampa.flirt.FlirtException:
                    _l.warning("Failed to load FLIRT signature file %s.", sig_path)
                    continue

                # is there a meta data file?
                meta_path = os.path.join(root, filename[:-4] + ".meta")
                if os.path.isfile(meta_path):
                    # yes!
                    with open(meta_path) as f:
                        meta = json.load(f)

                    arch = meta.get("arch", None)
                    platform = meta.get("platform", None)
                    os_name = meta.get("os", None)
                    os_version = meta.get("os_version", None)
                    compiler = meta.get("compiler", None)
                    compiler_version = meta.get("compiler_version", None)
                    unique_strings = meta.get("unique_strings", None)

                else:
                    # nope... we need to extract information from the signature file
                    # TODO: Convert them to angr-specific strings
                    arch = flirt_header.arch
                    platform = flirt_header.os_types
                    os_name = None
                    os_version = None
                    unique_strings = None
                    compiler = None
                    compiler_version = None

                signature = FlirtSignature(
                    arch,
                    platform,
                    flirt_header.library_name.decode("utf-8"),
                    sig_path,
                    unique_strings=unique_strings,
                    compiler=compiler,
                    compiler_version=compiler_version,
                    os_name=os_name,
                    os_version=os_version,
                )

                FLIRT_SIGNATURES_BY_ARCH[arch].append(signature)

    # fill in LIBRARY_TO_SIGNATURES and STRING_TO_LIBRARIES
    for sigs in FLIRT_SIGNATURES_BY_ARCH.values():
        for sig in sigs:
            LIBRARY_TO_SIGNATURES[sig.sig_name].append(sig)
            if sig.unique_strings:
                for us in sig.unique_strings:
                    STRING_TO_LIBRARIES[us].add(sig.sig_name)
