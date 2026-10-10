#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from angr.analyses import Decompiler
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestPhoenixConditionalReturnExit(unittest.TestCase):
    def test_ppc64_loop_exit_through_conditional_return(self):
        # __memchr_ppc leaves its eight-bytes-at-a-time loop for 0x10069584, "cmpdi cr7,r10,0; li r3,0; beqlr cr7".
        # VEX lifts the beqlr to a conditional jump to the next instruction (0x10069590, the loop successor) in front
        # of the return, so the loop exit is that jump while the block ends in the return. Structuring used to raise
        # TypeError on it; now the exit is a break, and the return of 0 is its other branch.
        bin_path = os.path.join(test_location, "ppc64el", "fauxware_static")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER,
            normalize=True,
            regions=[(0x10069480, 0x10069880)],
            function_starts=[0x10069480],
            force_complete_scan=False,
            symbols=False,
        )
        func = cfg.functions[0x10069480]

        d = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert d.codegen is not None and d.codegen.text is not None
        print_decompilation_result(d)
        text = d.codegen.text
        assert re.search(r"break;\s*else\s*return NULL;", text) is not None


if __name__ == "__main__":
    unittest.main()
