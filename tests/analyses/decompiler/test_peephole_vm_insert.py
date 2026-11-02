#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import archinfo

import angr
from angr.ailment.expression import BinaryOp, Const, Convert, Insert, Load, Register, UnaryOp
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import VMInsertSimplifier

from .ail_equivalence import equivalent


def _has_insert(expr) -> bool:
    if isinstance(expr, Insert):
        return True
    return any(_has_insert(op) for op in getattr(expr, "operands", None) or ())


class TestVMInsertSimplifier(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()
        self.opt = VMInsertSimplifier(self.proj, self.proj.kb, self.m)

    def _c(self, v, bits=64):
        return Const(self.m.next_atom(), v, bits)

    def _r(self, off, bits=64):
        return Register(self.m.next_atom(), off, bits)

    def _bin(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=a.bits if op != "Concat" else a.bits + b.bits)

    def _not(self, a):
        return UnaryOp(self.m.next_atom(), "BitwiseNeg", a, bits=a.bits)

    def _conv(self, a, to_bits, signed=False):
        return Convert(self.m.next_atom(), a.bits, to_bits, signed, a)

    def _ins(self, base, off, value):
        return Insert(self.m.next_atom(), base, self._c(off), value, archinfo.Endness.LE)

    def _load(self, bits):
        return Load(self.m.next_atom(), self._r(48), bits // 8, archinfo.Endness.LE)

    def _check(self, expr, insert_left=False):
        out = self.opt.optimize(expr)
        assert out is not None
        assert equivalent(expr, out)
        assert _has_insert(out) == insert_left
        return out

    def test_low_byte_masked_in_place(self):
        b = self._r(16)
        # and spl, 0xf0
        out = self._check(self._ins(b, 0, self._bin("And", self._conv(b, 8), self._c(0xF0, 8))))
        assert isinstance(out, BinaryOp) and out.op == "And" and out.operands[1].value == 0xFFFFFFFFFFFFFFF0

    def test_low_byte_xor_with_other_value(self):
        b, y = self._r(16), self._r(24, 8)
        out = self._check(self._ins(b, 0, self._bin("Xor", self._conv(b, 8), y)))
        assert isinstance(out, BinaryOp) and out.op == "Xor" and out.operands[0].likes(b)

    def test_complement_of_low_word(self):
        b = self._r(16, 32)
        out = self._check(self._ins(b, 0, self._not(self._conv(b, 16))))
        assert isinstance(out, BinaryOp) and out.op == "Xor" and out.operands[1].value == 0xFFFF

    def test_nor_of_low_byte(self):
        # Insert(Insert(b, 0, ~b8), 0, ~b8 & ~y): the VM's nor
        b, y = self._r(16), self._r(24, 8)
        inner = self._ins(b, 0, self._not(self._conv(b, 8)))
        expr = self._ins(inner, 0, self._bin("And", self._not(self._conv(b, 8)), self._not(y)))
        out = self.opt.optimize(expr)
        assert isinstance(out, Insert) and out.base.likes(b)
        self._check(out)

    def test_nand_is_left_alone(self):
        b, y = self._r(16), self._r(24, 8)
        assert self.opt.optimize(self._ins(b, 0, self._not(self._bin("And", self._conv(b, 8), y)))) is None

    def test_rewrite_of_own_bits_is_identity(self):
        x = self._r(16, 8)
        base = self._bin("Or", self._conv(x, 64), self._c(0x0D970000))
        out = self._check(self._ins(base, 0, self._conv(x, 16)))
        assert out.likes(base)

    def test_low_word_mask_through_or(self):
        x = self._r(16, 16)
        base = self._bin("Or", self._conv(x, 64), self._c(0x35610000))
        self._check(self._ins(base, 0, self._bin("And", x, self._c(0xFF, 16))))

    def test_second_byte(self):
        b, y = self._r(16), self._r(24, 8)
        low = self._conv(self._bin("Shr", b, self._c(8, 8)), 8)
        self._check(self._ins(b, 1, self._bin("Or", low, y)))

    def test_known_base(self):
        self._check(self._ins(self._bin("Concat", self._c(127, 16), self._c(0, 48)), 0, self._load(8)))
        y = self._r(24, 8)
        base = self._bin("Xor", self._conv(y, 64), self._c(185))
        out = self._check(self._ins(base, 0, self._bin("Add", y, self._c(3, 8))))
        assert isinstance(out, Convert)

    def test_constant_pulled_out_of_the_base(self):
        # Insert(v ^ 0x1B5AB5, 0, (v8 ^ w8) ^ 0xB5): the low byte of the constant is re-applied by the value
        v, w = self._r(16), self._r(24, 8)
        for op, k in (("Xor", 0x1B5AB5), ("Or", 0x1B5AB5), ("And", 0xFFFF00F0)):
            value = self._bin("Xor", self._bin("Xor", self._conv(v, 8), w), self._c(0xB5, 8))
            self._check(self._ins(self._bin(op, v, self._c(k)), 0, value))
        # nothing to gain: left alone
        assert self.opt.optimize(self._ins(self._bin("Xor", v, self._c(5)), 0, self._load(8))) is None

    def test_signed_base_with_unknown_sign_is_left_alone(self):
        y = self._r(24, 16)
        base = self._conv(y, 64, signed=True)
        assert self.opt.optimize(self._ins(base, 0, self._load(8))) is None

    def test_overwritten_insert(self):
        b, y, z = self._r(16), self._r(24, 8), self._r(32, 16)
        expr = self._ins(self._ins(b, 1, y), 0, z)
        out = self.opt.optimize(expr)
        assert isinstance(out, Insert) and out.base.likes(b)
        assert equivalent(expr, out)
        # a partly overlapping inner insert stays
        assert self.opt.optimize(self._ins(self._ins(b, 2, y), 0, z)) is None

    def test_narrowed_insert(self):
        b, y = self._r(16), self._r(24, 8)
        expr = self._conv(self._ins(b, 0, self._bin("Add", y, self._c(1, 8))), 16)
        out = self.opt.optimize(expr)
        assert isinstance(out, Insert) and out.bits == 16
        assert equivalent(expr, out)

    def test_insert_into_a_concat_half(self):
        hi, lo, v = self._r(16, 32), self._r(24, 32), self._r(32, 32)
        for off in (0, 4):
            out = self._check(self._ins(self._bin("Concat", hi, lo), off, v))
        assert isinstance(out, BinaryOp) and out.op == "Concat"

    def test_concat_of_adjacent_halves(self):
        from angr.ailment.expression import Extract

        x = self._r(16)
        hi = Extract(self.m.next_atom(), 32, x, self._c(4), archinfo.Endness.LE)
        for lo in (Extract(self.m.next_atom(), 32, x, self._c(0), archinfo.Endness.LE), self._conv(x, 32)):
            expr = self._bin("Concat", hi, lo)
            out = self.opt.optimize(expr)
            assert out is not None and out.likes(x) and equivalent(expr, out)
        # the halves of a narrower window
        hi16 = Extract(self.m.next_atom(), 16, x, self._c(2), archinfo.Endness.LE)
        expr = self._bin("Concat", hi16, self._conv(x, 16))
        out = self.opt.optimize(expr)
        assert isinstance(out, Convert) and equivalent(expr, out)
        # not adjacent
        assert (
            self.opt.optimize(
                self._bin("Concat", hi16, Extract(self.m.next_atom(), 16, x, self._c(4), archinfo.Endness.LE))
            )
            is None
        )

    def test_const_concat(self):
        out = self.opt.optimize(self._bin("Concat", self._c(0x7F, 16), self._c(5, 48)))
        assert isinstance(out, Const) and out.value == (0x7F << 48) | 5
        # aggregates are left alone
        assert self.opt.optimize(self._bin("Concat", self._c(80, 64), self._c(0, 768))) is None

    def test_exhaustive_byte_lifts(self):
        # every two-input bitwise function of the low byte and another byte, over every constant
        b, y = self._r(16, 16), self._r(24, 8)
        low = self._conv(b, 8)
        shapes = []
        for k in (0, 0x0F, 0xF0, 0xFF):
            c = self._c(k, 8)
            for op in ("And", "Or", "Xor"):
                shapes.append(self._bin(op, low, c))
                shapes.append(self._bin(op, self._not(low), c))
                shapes.append(self._bin(op, low, self._not(y)))
                shapes.append(self._not(self._bin(op, self._not(low), y)))
                shapes.append(self._bin(op, self._bin("Xor", low, c), self._bin("And", y, c)))
        rewritten = 0
        for v in shapes:
            expr = self._ins(b, 0, v)
            out = self.opt.optimize(expr)
            if out is not None:
                rewritten += 1
                assert equivalent(expr, out), v
        assert rewritten > len(shapes) // 2


if __name__ == "__main__":
    unittest.main()
