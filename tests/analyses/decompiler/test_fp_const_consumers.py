#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""
Float-valued AIL constants reaching integer-only consumers (bit tricks in peephole optimizations, integer
reference-value rendering in codegen).
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestFpConstConsumers(unittest.TestCase):
    def test_aarch64_libc_frexp_float_mul_under_shift(self):
        # (x MulF 2^54) Shr 52: RemoveRedundantShifts must not treat the FP multiplication as a shift-left
        bin_path = os.path.join(test_location, "aarch64", "libc.so.6")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x432E30, project_kwargs={"auto_load_libs": False})
        func = cfg.functions[0x432E30]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "1.8014398509481984e+16" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()
