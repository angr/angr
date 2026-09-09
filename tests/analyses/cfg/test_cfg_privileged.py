#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCfgPrivileged(unittest.TestCase):
    def test_cfgfast_privileged_fallthrough(self):
        # cli and sti lift to Ijk_Privileged with the following instruction as a concrete default exit
        bin_path = os.path.join(test_location, "i386", "bios.bin.elf")
        p = angr.Project(bin_path, auto_load_libs=False)
        cfg = p.analyses.CFGFast()

        privileged = 0
        for node in cfg.model.nodes():
            addr = node.addr
            if not node.size or node.is_simprocedure or not isinstance(addr, int):
                continue
            if p.factory.block(addr, size=node.size).vex_nostmt.jumpkind != "Ijk_Privileged":
                continue
            privileged += 1
            assert [succ.addr for succ in node.successors] == [addr + node.size]
        assert privileged

        # _start is a cli followed by a cld; without the fall-through _start is a one-byte non-returning
        # function and the cld starts a function of its own
        start = cfg.functions["_start"]
        assert start.addr == 0xFF06E
        assert {0xFF06E, 0xFF06F}.issubset(start.block_addrs_set)
        assert start.returning is not False
        assert 0xFF06F not in cfg.functions

    def test_cfgemulated_privileged_fallthrough(self):
        bin_path = os.path.join(test_location, "i386", "bios.bin.elf")
        p = angr.Project(bin_path, auto_load_libs=False)
        cfg = p.analyses.CFGEmulated(starts=(0xFF06E,), context_sensitivity_level=0)
        node = cfg.model.get_any_node(0xFF06E)
        assert node is not None
        assert [succ.addr for succ in node.successors] == [0xFF06F]
        assert {0xFF06E, 0xFF06F}.issubset(cfg.kb.functions[0xFF06E].block_addrs_set)


if __name__ == "__main__":
    unittest.main()
