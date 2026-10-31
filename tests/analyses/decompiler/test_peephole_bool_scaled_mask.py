#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import ITE, BinaryOp, Const, Convert, Expression, Register, UnaryOp
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import BoolScaledMask

from .test_peephole_vm_bool_select import _equivalent

WIDTHS = (8, 16, 32, 64)


def _eval(expr: Expression, b: int) -> int:
    """Concrete value of ``expr`` with the 1-bit register standing for ``b``."""
    mask = (1 << expr.bits) - 1
    if isinstance(expr, Const):
        return expr.value_int & mask
    if isinstance(expr, Register):
        return b
    if isinstance(expr, Convert):
        v = _eval(expr.operand, b)
        if expr.is_signed and expr.to_bits > expr.from_bits and v >> (expr.from_bits - 1):
            v -= 1 << expr.from_bits
        return v & mask
    if isinstance(expr, UnaryOp):
        assert expr.op == "Not"
        return _eval(expr.operand, b) ^ 1
    if isinstance(expr, ITE):
        return _eval(expr.iftrue if _eval(expr.cond, b) else expr.iffalse, b)
    a, c = (_eval(op, b) for op in expr.operands)
    return {
        "And": lambda: a & c,
        "Mul": lambda: (a * c) & mask,
        "Shl": lambda: (a << c) & mask,
        "Shr": lambda: a >> c,
        "CmpEQ": lambda: int(a == c),
        "CmpNE": lambda: int(a != c),
    }[expr.op]()


class TestBoolScaledMask(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()
        self.opt = BoolScaledMask(self.proj, self.proj.kb, self.m)
        self.b = Register(self.m.next_atom(), 16, 1)

    def _c(self, v, bits):
        return Const(self.m.next_atom(), v, bits)

    def _bin(self, op, a, b, bits=None):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=bits or a.bits)

    def _zext(self, b, bits):
        return Convert(self.m.next_atom(), 1, bits, False, b)

    def _ite(self, t, f, bits):
        return ITE(self.m.next_atom(), self.b, self._c(t, bits), self._c(f, bits))

    def _rewrite(self, expr):
        """Bottom-up to a fixed point, the way the block simplifier applies an expression peephole."""
        if isinstance(expr, BinaryOp):
            expr = BinaryOp(expr.idx, expr.op, [self._rewrite(o) for o in expr.operands], expr.signed, bits=expr.bits)
            out = self.opt.optimize(expr)
            return expr if out is None else self._rewrite(out)
        if isinstance(expr, Convert):
            return Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, self._rewrite(expr.operand))
        return expr

    def _forms(self, w, k):
        """``(zext(b) << k)`` masked down to bit ``k`` (or shifted back to bit 0), in every spelling."""
        p = 1 << k
        return [
            (self._bin("And", self._bin("Mul", self._zext(self.b, w), self._c(p, w)), self._c(p, w)), k),
            (self._bin("And", self._c(p, w), self._bin("Mul", self._c(p, w), self._zext(self.b, w))), k),
            (self._bin("And", self._bin("Shl", self._zext(self.b, w), self._c(k, 8)), self._c(p, w)), k),
            (
                self._bin(
                    "And",
                    self._bin("Shr", self._bin("Shl", self._zext(self.b, w), self._c(k, 8)), self._c(k, 8)),
                    self._c(1, w),
                ),
                0,
            ),
            (self._bin("And", self._ite(p, 0, w), self._c(p, w)), k),
            (self._bin("And", self._ite(0, p, w), self._c(p, w)), k),
        ]

    def test_exhaustive_widths_and_shifts(self):
        for w in WIDTHS:
            for k in range(w):
                for expr, bit in self._forms(w, k):
                    out = self._rewrite(expr)
                    assert out is not expr and not (isinstance(out, BinaryOp) and out.op == "And"), (w, k, expr)
                    for b in (0, 1):
                        assert _eval(out, b) == _eval(expr, b), (w, k, b, out)
                    assert {_eval(out, 0), _eval(out, 1)} == {0, 1 << bit}, (w, k, out)
                    for op in ("CmpNE", "CmpEQ"):
                        cond = self._rewrite(self._bin(op, expr, self._c(0, w), bits=1))
                        bare = isinstance(cond, BinaryOp) and isinstance(cond.operands[0], Convert)
                        assert cond.bits == 1 and (isinstance(cond, (Register, UnaryOp)) or bare), (w, k, op, cond)
                        for b in (0, 1):
                            assert _eval(cond, b) == int((_eval(expr, b) != 0) == (op == "CmpNE"))

    def test_themida_zero_flag_test(self):
        # if ((v0 == 5) * 64 & 64)
        zf = BinaryOp(
            self.m.next_atom(), "CmpEQ", [Register(self.m.next_atom(), 24, 32), self._c(5, 32)], False, bits=1
        )
        scaled = self._bin("Mul", self._zext(zf, 32), self._c(64, 32))
        expr = self._bin("CmpNE", self._bin("And", scaled, self._c(64, 32)), self._c(0, 32), bits=1)
        out = self._rewrite(expr)
        assert out.likes(zf)
        assert _equivalent(expr, out)
        # through a truncation to the low byte that keeps bit 6
        narrowed = Convert(self.m.next_atom(), 32, 8, False, scaled)
        expr = self._bin("CmpNE", self._bin("And", narrowed, self._c(64, 8)), self._c(0, 8), bits=1)
        assert self._rewrite(expr).likes(zf)

    def test_unchanged(self):
        w = 32
        zext = self._zext(self.b, w)
        cases = [
            # the mask misses the bit
            self._bin("And", self._bin("Mul", zext, self._c(64, w)), self._c(32, w)),
            # the bit is shifted out of the word
            self._bin(
                "And", self._bin("Mul", self._bin("Mul", zext, self._c(1 << 16, w)), self._c(1 << 16, w)), self._c(1, w)
            ),
            # a wider operand is not a boolean
            self._bin(
                "And",
                self._bin(
                    "Mul", Convert(self.m.next_atom(), 8, w, False, Register(self.m.next_atom(), 16, 8)), self._c(64, w)
                ),
                self._c(64, w),
            ),
            # sign-extension of a bool is 0 or -1
            self._bin(
                "And", self._bin("Mul", Convert(self.m.next_atom(), 1, w, True, self.b), self._c(64, w)), self._c(64, w)
            ),
            # shifting right past the bit
            self._bin("Shr", self._bin("Mul", zext, self._c(4, w)), self._c(3, 8)),
            # sign-extending the sign bit
            self._bin(
                "And",
                Convert(self.m.next_atom(), 8, w, True, self._bin("Mul", self._zext(self.b, 8), self._c(128, 8))),
                self._c(128, w),
            ),
        ]
        for expr in cases:
            assert self.opt.optimize(expr) is None, expr
        # a bare zext test is left to the conversion peepholes
        assert self.opt.optimize(self._bin("CmpNE", zext, self._c(0, w), bits=1)) is None


if __name__ == "__main__":
    unittest.main()
