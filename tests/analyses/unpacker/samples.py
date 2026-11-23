from __future__ import annotations

import os
import unittest

from tests.common import bin_location

IMAGE_BASE = 0x400000
IMAGE_BASE_64 = 0x140000000

# for tests of the Icicle engine that need fixes of the x86 SLEIGH files that pypcode does not have yet
needs_sleigh_fixes = unittest.skip("needs x86 SLEIGH fixes that pypcode does not have yet")


def sample_path(name: str, is_64bit: bool = False) -> str:
    """
    The path of a hand-made PE file of the unpacker tests; tests_src/unpacker/build.py in the binaries repo builds
    them and describes their code.
    """
    return os.path.join(bin_location, "tests", "x86_64" if is_64bit else "i386", "windows", "unpacker", name)


def sample(name: str, is_64bit: bool = False) -> bytes:
    with open(sample_path(name, is_64bit), "rb") as f:
        return f.read()
