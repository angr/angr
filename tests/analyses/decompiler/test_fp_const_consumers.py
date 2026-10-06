#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""
Float-valued AIL constants reaching integer-only consumers (bit tricks in peephole optimizations, integer
reference-value rendering in codegen).
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from angr.analyses import Decompiler
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestFpConstConsumers(unittest.TestCase):
    def test_aarch64_libc_frexp_float_mul_under_shift(self):
        # (x MulF 2^54) Shr 52: RemoveRedundantShifts must not treat the FP multiplication as a shift-left
        bin_path = os.path.join(test_location, "aarch64", "libc.so.6")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x432E30, project_kwargs={"auto_load_libs": False})
        func = cfg.functions[0x432E30]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert "1.8014398509481984e+16" in dec.codegen.text

    def test_aarch64_go_endcycle_float_const_as_int_typed_call_arg(self):
        # 0.3 is passed to runtime.printfloat whose recovered prototype types the slot as long long; the float
        # constant must render as a double literal instead of going through integer reference-value formatting
        bin_path = os.path.join(test_location, "aarch64", "langdetect_go_go1.17.13")
        proj, cfg = load_project_with_scoped_cfg(
            bin_path,
            0x2D330,
            extra_func_addrs=[0x43840],  # runtime.printfloat
            expand_call_tree=False,
            window=0x400,
            project_kwargs={"auto_load_libs": False},
        )
        func = cfg.functions[0x2D330]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert re.search(r"runtime\.printfloat\([^;]*\b0\.3\)", dec.codegen.text)


if __name__ == "__main__":
    unittest.main()
