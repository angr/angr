#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ...common import bin_location


test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCfgThumbFirmware(unittest.TestCase):
    def test_thumb_firmware_cfg(self):
        # Test an ARM firmware sample.
        #
        # This tests CFG, but also the Gym (the ThumbSpotter, etc)
        # Also requires proper relocs support, or You're Gonna Have a Bad Time(tm)
        # In short, a very comprehensive high level test

        path = os.path.join(test_location, "armel", "i2c_master_read-nucleol152re.elf")
        p = angr.Project(path, auto_load_libs=False)

        # This is the canonical way to carve up a nasty firmware thing.

        cfg = p.analyses.CFGFast(
            resolve_indirect_jumps=True, force_smart_scan=False, force_complete_scan=False, normalize=True
        )

        # vfprintf should return; this function has a weird C++ thing that gets compiled as a tail-call.
        # The function itself must return, and _NOT_ contain its callee.
        vfprintf = cfg.kb.functions[p.loader.find_symbol("vfprintf").rebased_addr]
        assert vfprintf.returning
        assert len(list(vfprintf.blocks)) == 1
        # The function should have one "transition"
        block = next(iter(vfprintf.endpoints_with_type["transition"]))
        assert len(block.successors()) == 1
        succ = next(iter(block.successors()))
        assert succ.addr == 0x080081DD
        f2 = p.kb.functions[succ.addr]
        assert f2.name == "_vfprintf_r"
        assert f2.returning


if __name__ == "__main__":
    unittest.main()
