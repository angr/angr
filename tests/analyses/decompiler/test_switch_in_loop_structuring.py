#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


def _decompile(bin_path: str, func_addr: int, size: int):
    proj = angr.Project(bin_path, auto_load_libs=False)
    start = func_addr & ~1
    cfg = proj.analyses.CFGFast(normalize=True, regions=[(start, start + size)], function_starts=[func_addr])
    dec = proj.analyses.Decompiler(func_addr, cfg=cfg.model)
    assert dec.codegen is not None and dec.codegen.text is not None
    print_decompilation_result(dec)
    assert dec.structuring_failures == []
    return dec.codegen.text


class TestSwitchInLoopStructuring(unittest.TestCase):
    def test_tar_name_next_elt_o0(self):
        # a jump-table switch inside a while loop: the default case continues (the loop head is the region head),
        # cases return, continue, or fall through into another case behind an if-then
        bin_path = os.path.join(test_location, "x86_64", "decbench_tar_O0_stripped")
        text = _decompile(bin_path, 0x42D244, 0x138)
        assert "goto *" not in text
        assert "switch (" in text
        assert "default:" in text
        # case 1 falls through into case 0 without a break
        assert re.search(r"case 1:\s*if \(a0\)\s*\{[^}]*continue;\s*\}\s*case 0:", text) is not None

    def test_tar_name_next_elt_o2(self):
        # the switch's default case jumps to the loop test block, which the loop head also reaches
        bin_path = os.path.join(test_location, "x86_64", "decbench_tar_O2_noinline_stripped")
        text = _decompile(bin_path, 0x4267D0, 0xFF)
        assert "goto *" not in text
        assert "switch (" in text
        for case_no in range(5):
            assert f"case {case_no}:" in text

    def test_crazyflie_follow_path(self):
        # a lowered (if-else chain) switch inside a loop; one of its cases exits the loop
        bin_path = os.path.join(test_location, "armel", "decbench_crazyflie_cf2_O0_stripped.elf")
        text = _decompile(bin_path, 0x80270A5, 0x138)
        assert "while (1)" in text
        assert "switch (" in text
        assert "case 0:" in text and "case 4:" in text

    def test_uboot_eficonfig_show_boot_selection(self):
        bin_path = os.path.join(test_location, "armel", "decbench_uboot_O2_noinline_stripped")
        text = _decompile(bin_path, 0x6080D3C0, 0x1E0)
        assert "while (1)" in text
        assert "switch (" in text
        assert "case 0:" in text

    def test_sdiff_edit(self):
        # a switch-case inside a loop whose cases exit both to an in-region node and to a successor of the region:
        # absorbing the case nodes re-hid the successor edge of the switch-case node, orphaning the loop's exit
        bin_path = os.path.join(test_location, "x86_64", "decbench_sdiff_O0_stripped")
        text = _decompile(bin_path, 0x405326, 0x7DD)
        assert "switch (" in text
        assert "execvp(" in text or "sub_" in text


if __name__ == "__main__":
    unittest.main()
