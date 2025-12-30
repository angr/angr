#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
import re

import angr

from tests.common import bin_location, print_decompilation_result, WORKER


test_location = os.path.join(bin_location, "tests")


class TestSemvarNaming(unittest.TestCase):
    def test_loop_counter_naming(self):
        bin_path = os.path.join(test_location, "x86_64", "test_semvar_naming")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER,
            fail_fast=True,
            normalize=True,
        )
        proj.analyses.CompleteCallingConventions()

        func = cfg.functions["sum_matrix"]
        assert func is not None
        dec = proj.analyses.Decompiler(func)
        # should not crash
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert re.search(r"for \(i = 0; i < [a-zA-Z0-9]+; i \+= 1\)", dec.codegen.text) is not None
        assert re.search(r"for \(j = 0; j < [a-zA-Z0-9]+; j \+= 1\)", dec.codegen.text) is not None


if __name__ == "__main__":
    unittest.main()
