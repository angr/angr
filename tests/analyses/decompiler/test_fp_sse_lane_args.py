#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
"""
Reads of unnamed SSE sub-lanes (movmskpd lifts to GET:I32 at xmm0+4 and xmm0+12) used to become register arguments
named after their VEX offset ("228"), and calling-convention analysis then crashed on arch.registers["228"].
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr.analyses.calling_convention.utils import reg_arg_from_span
from angr.calling_conventions import SimRegArg
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestFpSseLaneArgs(unittest.TestCase):
    def test_reg_arg_from_span_widens_unnamed_lanes(self):
        amd64 = archinfo.ArchAMD64()
        assert reg_arg_from_span(amd64, 72, 4) == SimRegArg("edi", 4)
        assert reg_arg_from_span(amd64, 228, 4) == SimRegArg("xmm0lq", 8)
        assert reg_arg_from_span(amd64, 236, 4) == SimRegArg("xmm0hq", 8)
        x86 = archinfo.ArchX86()
        assert reg_arg_from_span(x86, 280, 8) == SimRegArg("xmm7", 16)

    def test_movmskpd_on_fp_argument(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "known_patterns_libm_bits")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)

        func = cfg.functions["f_isinf"]
        assert func.prototype is not None
        assert [arg.reg_name for arg in func.calling_convention.arg_locs(func.prototype)] == ["xmm0"]

        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "f_isinf(double a0)" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()
