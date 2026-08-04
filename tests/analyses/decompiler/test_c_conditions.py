#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import re
import unittest

import angr
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

l = logging.getLogger(__name__)


class TestDecompilingCConditions(unittest.TestCase):
    def test_decompiling_c_conditions_gcc_O0(self):
        bin_path = os.path.join(test_location, "x86_64", "c_conditions_gcc_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)
        func = cfg.functions["main"]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # dump all conditions
        conditions = re.findall(r"if \((.*?)\)\n", dec.codegen.text)
        if not WORKER:
            print(conditions)
        # adjust this list once the decompilation output changes, but make sure the output is correct!
        assert conditions == [
            # !(a >> 8) & 1
            "!(char)(v0) >> 8",
            # !((a >> 8) & 1)
            "!(v0 & 0x100)",
            # !((a >> 8) & b)
            "!(v1 & (char)(v0) >> 8)",
            # (a >> 8) & 1
            "(v0 & 0x100)",
            # (a >> 31) & !b
            "(!v1 & (char)(v0) >> 31)",
            # ~(a >> 31) & !b
            "(!v1 & ~((char)(v0) >> 31))",
            # ~((a >> 31) & !b)
            "(!v1 & (char)(v0) >> 31) != 0xffffffff",
        ]


if __name__ == "__main__":
    unittest.main()
