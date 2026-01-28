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


class TestNarrowingExpressions(unittest.TestCase):
    def test_narrowing_expressions_after_making_callsite_only(self):
        # narrowing expressions before making callsites may incorrectly remove some definitions that the calls use
        # in this test case, the definition of ecx at block 0x4066E5 will be replaced by cl, but ecx is actually used
        # by the call at 0x4066F8
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "131252a8059fdbb12d77cd4711e597c45bb48e6d4bc3ddc808697a5e0488ff2c"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER,
            fail_fast=True,
            normalize=True,
            start_at_entry=False,
            regions=[(0x406480, 0x406480 + 5000)],
        )

        func = cfg.functions[0x406480]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        # should not crash!


if __name__ == "__main__":
    unittest.main()
