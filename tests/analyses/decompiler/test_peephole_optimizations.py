#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os

import unittest
import archinfo
import ailment
from ailment.expression import BinaryOp, Const
import angr
from angr.analyses.decompiler.peephole_optimizations import ConstantDereferences, EagerEvaluation

from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestPeepholeOptimizations(unittest.TestCase):
    def test_constant_dereference(self):
        # a = *(A) :=> a = the variable at at A iff
        # - A is a pointer that points to a read-only section.

        proj = angr.Project(os.path.join(test_location, "armel", "decompiler", "rm"), auto_load_libs=False)

        expr = ailment.Expr.Load(
            None,
            ailment.Expr.Const(None, None, 0xA000, proj.arch.bits),
            proj.arch.bytes,
            archinfo.Endness.LE,
            ins_addr=0x400100,
        )
        opt = ConstantDereferences(proj, proj.kb, 0)
        optimized = opt.optimize(expr)
        assert isinstance(optimized, ailment.Const)
        assert optimized.value == 0x183F8
        assert optimized.tags.get("ins_addr", None) == 0x400100, "Peephole optimizer lost tags."

        # multiple cases that no optimization should happen
        # a. Loading a pointer from a writable location
        expr = ailment.Expr.Load(None, ailment.Expr.Const(None, None, 0x21DF4, proj.arch.bits), 1, archinfo.Endness.LE)
        opt = ConstantDereferences(proj, proj.kb, 0)
        optimized = opt.optimize(expr)
        assert optimized is None

    def test_eager_eval_mod(self):
        proj = angr.load_shellcode(b"\x90", "AMD64")

        opt = EagerEvaluation(proj, proj.kb)

        # Optimize 12 % 5 --> 2
        expr = BinaryOp(None, "Mod", [Const(None, None, 12, 32), Const(None, None, 5, 32)])
        expr_opt = opt.optimize(expr)
        assert isinstance(expr_opt, Const)
        assert expr_opt.value == 2

        # Don't optimize x % 0
        expr = BinaryOp(None, "Mod", [Const(None, None, 12, 32), Const(None, None, 0, 32)])
        expr_opt = opt.optimize(expr)
        assert expr_opt is None


if __name__ == "__main__":
    unittest.main()
