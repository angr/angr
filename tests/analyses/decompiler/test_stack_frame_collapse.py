#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from angr.sim_variable import SimStackVariable
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestStackFrameCollapse(unittest.TestCase):
    """
    At O0 every local lives in the stack frame and rbp holds sp-8. A frame-pointer-relative access that survives
    expression folding as ``rbp - N`` used to be read by ssailification as an array spanning from the frame
    pointer, which merged every local of the function into one slot.
    """

    @staticmethod
    def _decompile(binary: str, func_name: str):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", binary)
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions.function(name=func_name)
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        return dec

    def test_bzip2_o0_decompress_keeps_its_locals(self):
        # two statements in this function are 14 levels deep, so the block simplifier used to refuse to replace
        # the rbp register with sp-8 in them
        dec = self._decompile("decbench_bzip2_O0", "BZ2_decompress")
        text = dec.codegen.text

        assert "&(&v" not in text
        stack_vars = [var for var in dec.codegen.cfunc.get_unified_local_vars() if isinstance(var, SimStackVariable)]
        assert len(stack_vars) >= 50
        assert max(var.size for var in stack_vars) <= 8

    def test_gzip_o0_fprint_off_reference_offset(self):
        # p = buf + sizeof buf: the reference must point past the end of the buffer, not before its start
        dec = self._decompile("decbench_gzip_O0", "fprint_off")
        text = dec.codegen.text

        assert re.search(r"= &v\d+ \+ \d+;", text) is not None
        assert re.search(r"&v\d+ - \d+", text) is None


if __name__ == "__main__":
    unittest.main()
