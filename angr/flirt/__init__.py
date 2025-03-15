# This submodule stores and manages FLIRT signatures
from __future__ import annotations

import os
import json
from collections import defaultdict
import logging

from angr.analyses.flirt import (
    FlirtSignature,
    FlirtSignatureParsed,
    FlirtSignatureError,
    flirt_arch_to_arch_name,
    flirt_os_type_to_os_name,
)


_l = logging.getLogger(__name__)


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
                        sig_parsed = FlirtSignatureParsed.parse(f)
                except FlirtSignatureError:
                    _l.warning("Failed to load FLIRT signature file %s.", sig_path)
                    continue

                # is there a meta data file?
                meta_path = os.path.join(root, filename[:-4] + ".meta")
                if os.path.isfile(meta_path):
                    # yes!
                    with open(meta_path) as f:
                        meta = json.load(f)

                    arch = str(meta.get("arch", "Unknown"))
                    platform = str(meta.get("platform", "UnknownOS"))
                    os_name = meta.get("os", None)
                    os_version = meta.get("os_version", None)
                    compiler = meta.get("compiler", None)
                    compiler_version = meta.get("compiler_version", None)
                    unique_strings = meta.get("unique_strings", None)

                else:
                    # nope... we need to extract information from the signature file
                    arch = flirt_arch_to_arch_name(sig_parsed.arch, sig_parsed.app_types)
                    platform = flirt_os_type_to_os_name(sig_parsed.os_types)
                    os_name = None
                    os_version = None
                    unique_strings = None
                    compiler = None
                    compiler_version = None

                signature = FlirtSignature(
                    arch,
                    platform,
                    sig_parsed.libname,
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
