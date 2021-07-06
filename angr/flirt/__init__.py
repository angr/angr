# This submodule stores and manages FLIRT signatures

from typing import Set, Optional
import os
import json

import nampa


class FlirtSignature:
    """
    This class describes a FLIRT signature.
    """
    def __init__(self, arch: str, platform: str, sig_name: str, sig_path: str,
                 unique_strings: Optional[Set[str]]=None,
                 compiler: Optional[str]=None,
                 compiler_version: Optional[str]=None):
        self.arch = arch
        self.platform = platform
        self.sig_name = sig_name
        self.sig_path = sig_path
        self.unique_strings = unique_strings
        self.compiler = compiler
        self.compiler_version = compiler_version


FS = FlirtSignature

FLIRT_SIGNATURES = [ ]


def load_signatures(path: str) -> None:
    """
    Recursively load all FLIRT signatures under a specific path.

    :param path:    Location of FLIRT signatures.
    """

    for root, dirname, filenames in os.walk(path):
        for filename in filenames:
            if filename.endswith(".sig"):
                # parse it
                sig_path = os.path.join(root, filename)
                with open(sig_path, "rb") as f:
                    flirt = nampa.parse_flirt_file(f)

                # is there a meta data file?
                meta_path = os.path.join(root, filename[:-4] + ".meta")
                if os.path.isfile(meta_path):
                    # yes!
                    with open(meta_path, "r") as f:
                        meta = json.load(f)

                    arch = meta.get("arch", None)
                    platform = meta.get("os", None)
                    compiler = meta.get("compiler", None)
                    compiler_version = meta.get("compiler_version", None)
                    unique_strings = meta.get("unique_strings", None)

                else:
                    # nope... we need to extract information from the signature file
                    # TODO: Convert them to angr-specific strings
                    arch = flirt.header.arch
                    platform = flirt.header.os_types
                    unique_strings = None
                    compiler = None
                    compiler_version = None

                signature = FlirtSignature(
                    arch,
                    platform,
                    flirt.header.library_name,
                    sig_path,
                    unique_strings=unique_strings,
                    compiler=compiler,
                    compiler_version=compiler_version,
                )

                FLIRT_SIGNATURES.append(signature)

