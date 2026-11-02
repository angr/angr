from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin
# pylint:disable=missing-class-docstring,no-self-use

import unittest

from angr.ailment.expression import BinaryOp, Const, Convert, VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.peephole_optimizations.remove_redundant_conversions import RemoveRedundantConversions

from .test_peephole_fp import _make_peephole


class TestConvAddConst(unittest.TestCase):
    def _opt(self, expr):
        return _make_peephole(RemoveRedundantConversions).optimize(expr)

    def _zext_byte(self):
        x = VirtualVariable(1, 10, 8, category=VirtualVariableCategory.REGISTER, oident=16)
        return x, Convert(2, 8, 32, False, x)

    def test_add_of_a_wide_constant_stays_wide(self):
        # 0x6025a0 + zext(x) is an address into a table; truncating the constant to 0xa0 loses its base
        _, zext = self._zext_byte()
        assert self._opt(BinaryOp(3, "Add", [zext, Const(4, 0x6025A0, 32)], False)) is None

    def test_add_of_a_narrow_constant_moves_inside(self):
        x, zext = self._zext_byte()
        r = self._opt(BinaryOp(3, "Add", [zext, Const(4, 10, 32)], False))
        assert isinstance(r, Convert) and r.operand.op == "Add" and r.operand.operands[0].likes(x)
        assert r.operand.operands[1].value == 10 and r.operand.operands[1].bits == 8
        # x - 1 written as x + 0xffffffff still narrows
        r = self._opt(BinaryOp(5, "Add", [zext, Const(6, 0xFFFFFFFF, 32)], False))
        assert isinstance(r, Convert) and r.operand.operands[1].bits == 8


if __name__ == "__main__":
    unittest.main()
