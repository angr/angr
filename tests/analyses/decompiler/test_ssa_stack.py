#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr

from tests.common import bin_location, print_decompilation_result, WORKER

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestSSAStack(unittest.TestCase):
    def test_missing_stack_defs(self):
        bin_path = os.path.join(
            test_location,
            "i386",
            "windows",
            "22322afab6d7b2b21e715ff2568b02454ac39fb6a5fe305537bb529e106e407b",
        )
        proj = angr.Project(bin_path)
        cfg = proj.analyses.CFG(data_references=True, normalize=True, show_progressbar=not WORKER)

        func = cfg.functions[0x4720B2]
        dec = proj.analyses.Decompiler(func, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        # basic sanity check
        assert "WideCharToMultiByte(" in dec.codegen.text
        assert "CreateDCA(" in dec.codegen.text
        assert '"DISPLAY"' in dec.codegen.text

    def test_incorrect_narrowing_of_phi_vars(self):
        bin_path = os.path.join(
            test_location,
            "x86_64",
            "windows",
            "28ce9dfc983d8489242743635c792d3fc53a45c96316b5854301f6fa514df55e.sys",
        )
        proj = angr.Project(bin_path)
        cfg = proj.analyses.CFG(data_references=True, normalize=True, show_progressbar=not WORKER)

        func = cfg.functions[0x14001A314]
        dec = proj.analyses.Decompiler(func, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        # basic sanity check
        lines = dec.codegen.text.splitlines()
        assert len(lines) >= 100


if __name__ == "__main__":
    unittest.main()
