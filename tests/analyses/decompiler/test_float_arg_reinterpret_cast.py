#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestFloatArgReinterpretCast(unittest.TestCase):
    def test_double_arg_passed_as_plain_variable(self):
        # CRT _frexp-like routine: the two incoming stack args (double, int*) are read through one straddling
        # 4-byte load, so they become a single 12-byte stack variable and the double is passed to the callee as a
        # 64-bit Extract of it. with the callee parameter typed double, the argument must be the plain variable
        # rather than a `*((unsigned long long *)&a0)` bit-pattern view.
        bin_path = os.path.join(
            test_location, "i386", "windows", "22322afab6d7b2b21e715ff2568b02454ac39fb6a5fe305537bb529e106e407b"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)
        caller, callee = 0x423286, 0x42319F
        cfg = proj.analyses.CFGFast(
            function_starts=[caller, callee],
            start_at_entry=False,
            normalize=True,
            data_references=True,
            symbols=False,
            function_prologues=False,
            force_smart_scan=False,
            regions=[(callee, caller + 0x100)],
        )
        proj.analyses.CompleteCallingConventions(
            recover_variables=False, prioritize_func_addrs=[callee, caller], skip_other_funcs=True
        )
        callee_proto = cfg.kb.functions[callee].prototype
        assert callee_proto is not None
        assert isinstance(callee_proto.args[0], angr.sim_type.SimTypeDouble)

        d = proj.analyses.Decompiler(cfg.kb.functions[caller], cfg=cfg.model, fail_fast=True)
        assert d.codegen is not None and d.codegen.text is not None
        text = d.codegen.text
        assert "double a0" in text
        assert "sub_42319f(a0, 0)" in text


if __name__ == "__main__":
    unittest.main()
