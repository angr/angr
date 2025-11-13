#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr

from tests.common import bin_location, print_decompilation_result, WORKER


test_location = os.path.join(bin_location, "tests")

l = logging.Logger(__name__)


class TestPeepholeRedundantBitshifts(unittest.TestCase):
    def test_remove_redundant_bitshifts_around_comparators_incorrect_constant_sizes(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "1309c8993adeb587e629615eb6838a280f0a1faa6ac74fdb11b80d5bddc1c94f"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER, fail_fast=True, normalize=True, regions=[(0x140089620, 0x140089620 + 5000)]
        )
        proj.analyses.CompleteCallingConventions()
        func = cfg.functions[0x140089620]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        # should not crash!


if __name__ == "__main__":
    unittest.main()
