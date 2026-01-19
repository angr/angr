#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest
import re

import angr

from tests.common import bin_location, print_decompilation_result, WORKER

test_location = os.path.join(bin_location, "tests")

l = logging.Logger(__name__)


class TestPeepholeInlineMemset(unittest.TestCase):
    def test_03fb29da_inlined_memset(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "03fb29dab8ab848f15852a37a1c04aa65289c0160d9200dceff64d890b3290dd"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(
            show_progressbar=not WORKER,
            fail_fast=True,
            normalize=True,
            start_at_entry=False,
            regions=[(0x5E1020, 0x5E2010 + 0x1000)],
        )

        func = cfg.functions[0x5E2010]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg, options=[("semvar_naming", False)])
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert re.search(r"memset\(v\d+, 0, 72\);", dec.codegen.text) is not None
        assert re.search(r"memset\(v\d+[^,]+, 0, 40\);", dec.codegen.text) is not None


if __name__ == "__main__":
    unittest.main()
