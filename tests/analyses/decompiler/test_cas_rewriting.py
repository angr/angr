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


class TestCASRewriting(unittest.TestCase):
    def test_9c75d43e_cas_intrinsics(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "9c75d43ec531c76caa65de86dcac0269d6727ba4ec74fe1cac1fda0e176fd2ab"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)
        func = cfg.functions[0x140002F50]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert "CasCmp" not in dec.codegen.text
        assert dec.codegen.text.count("InterlockedIncrement") == 4
        assert dec.codegen.text.count("InterlockedExchange64") == 1
        assert dec.codegen.text.count("InterlockedExchangeAdd") == 1
        assert dec.codegen.text.count("InterlockedDecrement") == 1

        func = cfg.functions[0x1400036C0]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert "CasCmp" not in dec.codegen.text
        assert dec.codegen.text.count("InterlockedExchange64") == 3
        assert dec.codegen.text.count("InterlockedExchangeAdd") == 1
        assert dec.codegen.text.count("InterlockedDecrement") == 1


if __name__ == "__main__":
    unittest.main()
