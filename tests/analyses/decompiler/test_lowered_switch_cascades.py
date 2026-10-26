#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
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


class TestLoweredSwitchCascades(unittest.TestCase):
    def test_dash_xxreadtoken(self):
        # an if-chain in front of a 51-entry jump table: the chain's unrecognized range check used to be dropped as a
        # redundant comparison together with the whole jump table
        bin_path = os.path.join(test_location, "x86_64", "decbench_dash_O0_stripped")
        text = _decompile(bin_path, 0x413C71, 0x20A)
        assert "goto *" not in text
        assert "switch (" in text
        for case_no in (10, 35, 38, 40, 41, 59):
            assert f"case {case_no}:" in text
        assert "sub_413f69(" in text  # the default case body

    def test_tar_maybe_recoverable(self):
        # the case target block was duplicated with a new block index, which cut the cascade short
        bin_path = os.path.join(test_location, "x86_64", "decbench_tar_O0_stripped")
        text = _decompile(bin_path, 0x419950, 0x27E)
        assert "case 17:" in text
        assert "case 2:" in text
        assert "goto LABEL_419b86;" in text  # the duplicated block's continuation is kept

    def test_grep_fgrep_to_grep_pattern(self):
        # a "== -1" comparison stops the cascade walk; the cascade must be rejected instead of leaking the comparison
        # node as an undeclared successor of the switch head
        bin_path = os.path.join(test_location, "x86_64", "decbench_grep_O0_stripped")
        text = _decompile(bin_path, 0x40A32F, 0x1A4)
        assert "mempcpy(" in text
        assert "memset(" in text

    def test_crontab_edit_cmd(self):
        bin_path = os.path.join(test_location, "x86_64", "decbench_crontab_O0_stripped")
        text = _decompile(bin_path, 0x404FE9, 0xA98)
        assert "switch (" in text

    def test_dash_umaskcmd(self):
        bin_path = os.path.join(test_location, "x86_64", "decbench_dash_O2_noinline_stripped")
        text = _decompile(bin_path, 0x40E620, 0x502)
        assert "switch (" in text

    def test_betaflight_process_smartport_telemetry_shared_loop_head(self):
        # two cascades share the loop head as their default. copying it for the switch heads used to drop its other
        # in-edges, which silently removed the whole loop
        bin_path = os.path.join(test_location, "armel", "decbench_betaflight_STM32F405_O2_noinline_stripped.elf")
        text = _decompile(bin_path, 0x805C415, 0x760)
        assert "while (" in text
        assert text.count("sub_805bde5(") >= 20  # smartPortSendPackage, called throughout the loop

    def test_uboot_do_env_delete_two_comparisons(self):
        # a two-comparison loop (`c == 0` / `c == 'f'`): the leftover default must not make it a switch
        bin_path = os.path.join(test_location, "armel", "decbench_uboot_O2_noinline_stripped")
        text = _decompile(bin_path, 0x60813F3C, 0xB0)
        assert "switch (" not in text
        assert "while (1)" in text


if __name__ == "__main__":
    unittest.main()
