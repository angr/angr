#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class PatchTests(unittest.TestCase):
    """
    Basic PatchManager tests
    """

    def test_patch_vulnerable_fauxware_amd64(self):
        binpath = os.path.join(test_location, "x86_64", "vulns", "vulnerable_fauxware")
        proj = angr.Project(binpath, auto_load_libs=False)

        proj.kb.patches.add_patch(0x40094C, b"\x0a")
        patched = proj.kb.patches.apply_patches_to_binary()

        # manual patch
        with open(binpath, "rb") as f:
            binary_data = f.read()
        binary_data = binary_data[:0x94C] + b"\x0a" + binary_data[0x94D:]

        assert patched == binary_data

    def test_block_factory_returns_patched_bytes(self):
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(binpath, auto_load_libs=False)

        addr = 0x4007D3
        patch_bytes = proj.arch.keystone.asm("inc rax; leave; ret", addr, as_bytes=True)[0]
        proj.kb.patches.add_patch(addr, patch_bytes)

        b = proj.factory.block(addr)
        assert b.bytes == patch_bytes


if __name__ == "__main__":
    unittest.main()
