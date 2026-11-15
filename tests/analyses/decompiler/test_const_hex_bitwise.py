# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.ailment import Expr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestConstHexBitwise(unittest.TestCase):
    """A constant that is a direct operand of a bitwise And/Or/Xor is displayed in hexadecimal."""

    @classmethod
    def setUpClass(cls):
        proj = angr.Project(
            os.path.join(test_location, "x86_64", "decompiler", "known_patterns_ctype"), auto_load_libs=False
        )
        cfg = proj.analyses.CFGFast(normalize=True)
        cls.dec = proj.analyses.Decompiler(cfg.functions["space_or_alnum"], cfg=cfg.model, fail_fast=True)

    def _c(self, expr) -> str:
        return self.dec.codegen._handle(expr).c_repr()

    @staticmethod
    def _binop(op, lhs, rhs, bits=32):
        return Expr.BinaryOp(None, op, [lhs, rhs], bits=bits)

    def test_decompiled_mask(self):
        text = self.dec.codegen.text
        assert "& 0x2008" in text
        assert "8200" not in text

    def test_bitwise_operands(self):
        x = Expr.Register(None, 16, 32)
        for op in ("And", "Or", "Xor"):
            for value in (16386, 280, 1301, 2363394, 0x49534F50):
                for operands in ([x, Expr.Const(None, value, 32)], [Expr.Const(None, value, 32), x]):
                    text = self._c(self._binop(op, *operands))
                    assert hex(value) in text and str(value) not in text, text

    def test_kept_in_decimal(self):
        x = Expr.Register(None, 16, 32)
        y = Expr.Register(None, 24, 32)

        def const(v):
            return Expr.Const(None, v, 32)

        # below 256, and the decimal rules
        for value in (10, 100, 254, 5000, 10000, 111112):
            text = self._c(self._binop("And", x, const(value)))
            assert str(value) in text and hex(value) not in text, text
        # other operators
        for op in ("Add", "Sub", "Mul", "CmpEQ"):
            text = self._c(self._binop(op, x, const(12345)))
            assert "12345" in text and "0x3039" not in text, text
        # only a direct operand
        text = self._c(self._binop("Xor", self._binop("Mul", x, const(3266489917)), y))
        assert "3266489917" in text, text
        text = self._c(self._binop("And", self._binop("Add", x, const(12345)), const(1301)))
        assert "12345" in text and "0x515" in text, text
        # a negated condition selects a number
        cond = Expr.Convert(None, 1, 32, False, self._binop("CmpEQ", y, const(0), bits=1))
        neg = Expr.UnaryOp(None, "Neg", cond, bits=32)
        for operands in ([neg, const(362500)], [const(362500), neg]):
            text = self._c(self._binop("And", *operands))
            assert "362500" in text, text
        text = self._c(self._binop("Or", neg, const(362501)))
        assert "0x58805" in text, text


if __name__ == "__main__":
    unittest.main()
