#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from tests.common import bin_location, print_decompilation_result, WORKER

test_location = os.path.join(bin_location, "tests")


class TestPropagatorRules(unittest.TestCase):
    def test_propagator_do_not_propagate_constants_through_unsafe_stack_variables(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "03fb29dab8ab848f15852a37a1c04aa65289c0160d9200dceff64d890b3290dd"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)

        func = cfg.functions[0x13640]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # incorrect propagation of stack variable at bp-0x10 will result in missing code blocks and function calls
        assert dec.codegen.text.count("ObfDereferenceObject(") == 1
        assert dec.codegen.text.count("ObReferenceObjectByPointer(") == 1
        assert dec.codegen.text.count("ExFreePoolWithTag") == 1

    def test_propagator_do_not_create_overly_deep_expressions(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "94def0c6290dbc32ebb9a6e72d2f76d0ffe66365606efeef952834768e47f1d8"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)

        func = cfg.functions[0x14000F190]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # ensure that each line contains at most five operators
        for line in dec.codegen.text.splitlines():
            if line.strip() == "":
                continue
            op_count = line.count("+") + line.count("-") + line.count("^") + line.count("ROL") + line.count("ROR")
            if "return" in line:
                assert op_count <= 12
            else:
                assert op_count <= 7


if __name__ == "__main__":
    unittest.main()
