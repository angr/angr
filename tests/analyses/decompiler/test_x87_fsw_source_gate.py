#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Convert, Tmp
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.peephole_optimizations.x87_cmpf import X87CmpF
from angr.analyses.decompiler.utils import peephole_optimize_exprs
from angr.analyses.decompiler.x87_fsw import block_has_fsw_source, expr_has_fsw_source


def _a(n):
    return Tmp(None, n, 64)


class TestX87FswSourceGate(unittest.TestCase):
    def test_integer_block_has_no_source(self):
        stmts = [Assignment(0, _a(1), BinaryOp(None, "And", [_a(2), Const(None, 0x45, 64)], False, bits=64))]
        assert not block_has_fsw_source(stmts)

    def test_sources(self):
        x, y = Tmp(None, 3, 64), Tmp(None, 4, 64)
        cmpf = BinaryOp(None, "CmpF", [x, y], False, bits=32)
        assert block_has_fsw_source([Assignment(0, _a(1), BinaryOp(None, "And", [cmpf, Const(None, 0x45, 32)], False))])
        # anything that a rewrite may turn into a C2 boolean (cond * 0x400, cond << 10)
        assert expr_has_fsw_source(BinaryOp(None, "Shl", [_a(2), Const(None, 10, 8)], False, bits=64))
        assert expr_has_fsw_source(BinaryOp(None, "Mul", [_a(2), Const(None, 0x400, 64)], False, bits=64))

    def test_fold_still_applies_with_a_source(self):
        # (CmpF(a, b) & 0x45) == 0 -> a > b
        x, y = Tmp(None, 3, 64), Tmp(None, 4, 64)
        cmpf = BinaryOp(None, "CmpF", [x, y], False, bits=32, floating_point=True)
        masked = BinaryOp(None, "And", [cmpf, Const(None, 0x45, 32)], False, bits=32)
        cond = BinaryOp(None, "CmpEQ", [masked, Const(None, 0, 32)], False, bits=1)
        block = Block(0x1000, 4, statements=[Assignment(0, _a(1), Convert(None, 1, 64, False, cond))])
        opt = X87CmpF(None, None, Manager())
        assert peephole_optimize_exprs(block, [opt])


if __name__ == "__main__":
    unittest.main()
