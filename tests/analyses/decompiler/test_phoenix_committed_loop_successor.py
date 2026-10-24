#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
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


class TestPhoenixCommittedLoopSuccessor(unittest.TestCase):
    """
    Cyclic refinement marks the exits of a loop to the successor it picks. The loop that is eventually structured
    must use that successor: a later refinement or cyclic schema that picks another one leaves the marked exits
    pending forever, and the region never collapses.
    """

    def test_freertos_vqueueaddtoregistry_rerefinement(self):
        # a second refinement saw the committed exit hidden and picked a body node as the do-while successor
        bin_path = os.path.join(test_location, "armel", "decbench_freertos_RTOSDemo_O2_noinline_stripped.out")
        text = _decompile(bin_path, 0x2131, 0x60)
        assert "while (1)" in text
        assert text.count("== 10)") == 2 and text.count("break;") >= 2
        assert "LABEL_" not in text

    def test_uboot_cli_simple_process_macros_partial_while(self):
        # a while loop formed around part of the refined loop's body, outliving the marks of the other body nodes
        bin_path = os.path.join(test_location, "armel", "decbench_uboot_O2_noinline_stripped")
        text = _decompile(bin_path, 0x60816F64, 0x2D0)
        assert "while (" in text


if __name__ == "__main__":
    unittest.main()
