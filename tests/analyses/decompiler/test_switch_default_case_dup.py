#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from tests.common import bin_location, print_decompilation_result, WORKER

test_location = os.path.join(bin_location, "tests")


class TestSwitchDefaultCaseDuplicator(unittest.TestCase):
    def test_switch_case_header_mismatch_caused_by_cmovs(self):
        bin_path = os.path.join(
            test_location, "i386", "windows", "a71a3c3b922705cb5e2d8aa9c74f5c73c47fb27f10b1327eb2bb054d99a14397"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER,
            fail_fast=True,
            normalize=True,
            regions=[(0x556D90, 0x556D90 + 5000), (0x64EA20, 0x64EA20 + 5000)],
            function_starts=[0x64EA20],
        )
        proj.analyses.CompleteCallingConventions(fail_fast=True)

        func = cfg.functions[0x64EA20]
        assert func is not None
        dec = proj.analyses.Decompiler(func, fail_fast=True)
        # should not crash
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)


if __name__ == "__main__":
    unittest.main()
