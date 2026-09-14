#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
"""Tests for return values that a 32-bit calling convention splits across two registers."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.ailment import Stmt
from angr.analyses.decompiler import Decompiler
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestSplitReturnValues(unittest.TestCase):
    @staticmethod
    def _decompile(func_name: str):
        bin_path = os.path.join(test_location, "i386", "nl")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        func = cfg.functions[func_name]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert dec.clinic is not None and dec.clinic.graph is not None
        print_decompilation_result(dec)
        returns = [stmt for block in dec.clinic.graph for stmt in block.statements if isinstance(stmt, Stmt.Return)]
        return func, returns

    def test_udivdi3_returns_eax_and_edx(self):
        # cdecl returns a 64-bit value in eax:edx. Calling convention analysis reports a 32-bit return type for
        # __udivdi3 and type inference widens it to 64 bits eleven Clinic stages later, so the return statements
        # used to keep only the eax half.
        func, returns = self._decompile("__udivdi3")

        assert func.prototype is not None and func.prototype.returnty is not None
        assert func.prototype.returnty.size == 64
        assert returns
        for stmt in returns:
            assert sum(expr.bits for expr in stmt.ret_exprs) == 64

    def test_single_register_return_is_left_alone(self):
        # xstrdup returns one register's worth; edx is caller-saved scratch there and must not be returned
        func, returns = self._decompile("xstrdup")

        assert func.prototype is not None and func.prototype.returnty is not None
        assert func.prototype.returnty.size == 32
        assert returns
        for stmt in returns:
            assert sum(expr.bits for expr in stmt.ret_exprs) == 32


if __name__ == "__main__":
    unittest.main()
