#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import itertools
import random
import unittest

import angr
from angr.ailment.expression import BinaryOp, Const, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import ComplementCompare, OrderedOrEqual, SignOverflowCompare

from .ail_equivalence import equivalent


class TestSignOverflowCompare(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()
        self.lt = SignOverflowCompare(self.proj, self.proj.kb, self.m)
        self.le = OrderedOrEqual(self.proj, self.proj.kb, self.m)

    def _c(self, v, bits):
        return Const(self.m.next_atom(), v & ((1 << bits) - 1), bits)

    def _v(self, varid, bits):
        return VirtualVariable(self.m.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=8 * varid)

    def _bin(self, op, a, b, bits=None, signed=False):
        return BinaryOp(self.m.next_atom(), op, [a, b], signed, bits=bits or a.bits)

    def _neg(self, e):
        return UnaryOp(self.m.next_atom(), "BitwiseNeg", e, bits=e.bits)

    def _sign(self, e, ge=False):
        return self._bin("CmpGE" if ge else "CmpLT", e, self._c(0, e.bits), 1, signed=True)

    def _differ(self, r, ov, form):
        """sign(r) != sign(ov) in one of its spellings"""
        if form == 0:
            return self._bin("CmpNE", self._sign(r), self._sign(ov), 1)
        if form == 1:
            return self._bin("CmpEQ", self._sign(r, True), self._sign(ov), 1)
        if form == 2:
            return self._bin("Xor", self._sign(ov, True), self._sign(r, True), 1)
        either = self._bin("LogicalOr", self._sign(ov, True), self._sign(r, True), 1)
        return self._bin("LogicalAnd", either, self._bin("LogicalOr", self._sign(r), self._sign(ov), 1), 1)

    def _add_ov(self, x, y, s, which=0):
        return self._bin("And", self._neg(self._bin("Xor", x, y)), self._bin("Xor", (x, y)[which], s))

    def _sub_ov(self, x, y, d, which=0):
        return self._bin("And", self._bin("Xor", x, y), self._bin("Xor", (x, y)[which], d))

    def _operands(self, bits):
        v, w = self._v(1, bits), self._v(2, bits)
        top = 1 << (bits - 1)
        yield from ((v, w), (self._neg(v), w), (v, self._neg(w)))
        for c in (0, 16, top, 2 * top - 1):
            yield self._c(c, bits), v
            yield v, self._c(c, bits)

    def test_sf_ne_of(self):
        rng = random.Random(0)
        for bits in (8, 32):
            for x, y in self._operands(bits):
                for sub, comp, which in itertools.product((False, True), (False, True), (0, 1)):
                    if sub and which:
                        continue
                    res = self._bin("Sub" if sub else "Add", x, y)
                    ov = (self._sub_ov if sub else self._add_ov)(x, y, res, which)
                    r = self._neg(res) if comp else res
                    if rng.random() < 0.5:
                        r = self._bin("And", r, r)
                    expr = self._differ(r, ov, rng.randrange(4))
                    if rng.random() < 0.5:
                        expr = self._bin("CmpEQ", self._sign(r), self._sign(ov), 1)
                    out = self.lt.optimize(expr)
                    assert out is not None and out.op in ("CmpLT", "CmpGE", "CmpLE", "CmpGT") and out.signed, expr
                    assert out.depth <= 3
                    assert equivalent(expr, out), expr

    def test_every_spelling(self):
        x, y = self._v(1, 32), self._v(2, 32)
        d = self._bin("Sub", x, y)
        for form in range(4):
            out = self.lt.optimize(self._differ(d, self._sub_ov(x, y, d), form))
            assert out.op == "CmpLT" and out.signed and out.operands[0].likes(x) and out.operands[1].likes(y)
        both = self._bin("LogicalAnd", self._sign(d), self._sign(self._sub_ov(x, y, d)), 1)
        neither = self._bin("LogicalAnd", self._sign(d, True), self._sign(self._sub_ov(x, y, d), True), 1)
        out = self.lt.optimize(self._bin("LogicalOr", both, neither, 1))
        assert out.op == "CmpGE" and out.signed and out.operands[0].likes(x) and out.operands[1].likes(y)
        below = self._bin("CmpLE", d, self._c(-1, 32), 1, signed=True)
        above = self._bin("CmpGT", self._sub_ov(x, y, d), self._c(-1, 32), 1, signed=True)
        out = self.lt.optimize(self._bin("CmpEQ", below, above, 1))
        assert out.op == "CmpLT" and out.signed and out.operands[0].likes(x) and out.operands[1].likes(y)
        # the result as the pipeline leaves it: 4 - v for ~v + 5, v - 5 for its complement
        v, five = self._v(1, 32), self._c(5, 32)
        s = self._bin("Sub", self._c(4, 32), v)
        ov = self._add_ov(self._neg(v), five, s)
        expr = self._bin("CmpNE", self._sign(ov, True), self._sign(self._bin("Sub", v, five), True), 1)
        out = self.lt.optimize(expr)
        assert out.op == "CmpLT" and out.signed and out.operands[0].likes(v) and out.operands[1].value_int == 5
        assert equivalent(expr, out)

    def test_sf_ne_of_refusals(self):
        x, y, z = self._v(1, 32), self._v(2, 32), self._v(3, 32)
        s, d = self._bin("Add", x, y), self._bin("Sub", x, y)
        ne = lambda a, b: self._bin("CmpNE", a, b, 1)
        # overflow of another sum, of the subtrahend, an unsigned test, a test against another constant
        assert self.lt.optimize(ne(self._sign(s), self._sign(self._add_ov(x, z, self._bin("Add", x, z))))) is None
        assert self.lt.optimize(ne(self._sign(s), self._sign(self._add_ov(x, z, s)))) is None
        assert self.lt.optimize(ne(self._sign(d), self._sign(self._sub_ov(x, y, d, 1)))) is None
        assert self.lt.optimize(ne(self._sign(d), self._sign(self._add_ov(x, y, d)))) is None
        ov = self._add_ov(x, y, s)
        either = self._bin("LogicalOr", self._sign(s), self._sign(ov), 1)
        assert self.lt.optimize(self._bin("LogicalAnd", either, self._bin("LogicalOr", self._sign(s, True), self._sign(ov), 1), 1)) is None
        assert self.lt.optimize(ne(self._bin("CmpLT", s, self._c(0, 32), 1), self._sign(ov))) is None
        assert self.lt.optimize(ne(self._bin("CmpLT", s, self._c(1, 32), 1, signed=True), self._sign(ov))) is None

    def test_ordered_or_equal(self):
        for bits in (8, 32):
            a, b = self._v(1, bits), self._v(2, bits)
            zero = self._c(0, bits)
            for p, q in ((a, b), (b, a), (a, self._c(5, bits)), (self._c(0xEF, bits), a), (a, zero)):
                eqs = [
                    lambda op: self._bin(op, p, q, 1),
                    lambda op: self._bin(op, q, p, 1),
                    lambda op: self._bin(op, self._bin("Sub", p, q), zero, 1),
                    lambda op: self._bin(op, self._bin("Xor", q, p), zero, 1),
                    lambda op: self._bin(op, self._neg(self._bin("Add", self._neg(p), q)), zero, 1),
                    lambda op: self._bin(op, self._neg(self._bin("Add", p, self._neg(q))), zero, 1),
                ]
                for signed, eq, flip in itertools.product((False, True), eqs, (False, True)):
                    for logic, eq_op, order, merged in (
                        ("LogicalOr", "CmpEQ", "CmpLT", "CmpLE"),
                        ("LogicalOr", "CmpEQ", "CmpGT", "CmpGE"),
                        ("LogicalAnd", "CmpNE", "CmpGE", "CmpGT"),
                        ("LogicalAnd", "CmpNE", "CmpLE", "CmpLT"),
                    ):
                        operands = [self._bin(order, p, q, 1, signed=signed), eq(eq_op)]
                        expr = self._bin(logic, *(operands[::-1] if flip else operands), 1)
                        out = self.le.optimize(expr)
                        assert out is not None and out.op == merged and out.signed == signed, expr
                        assert equivalent(expr, out), expr

    def test_the_vm_spelling_of_less_or_equal(self):
        # ~(c + v) is ~c - v: its SF != OF || ZF is ~c <= v
        v, c = self._v(1, 32), self._c(16, 32)
        s = self._bin("Add", c, v)
        r = self._bin("And", self._neg(s), self._neg(s))
        less = self._bin("CmpNE", self._sign(r), self._sign(self._add_ov(c, v, s)), 1)
        expr = self._bin("LogicalOr", less, self._bin("CmpEQ", r, self._c(0, 32), 1), 1)
        lt = self.lt.optimize(less)
        out = self.le.optimize(self._bin("LogicalOr", lt, expr.operands[1], 1))
        assert out.op == "CmpGE" and out.signed and out.operands[0].likes(v) and out.operands[1].value_int == 0xFFFFFFEF
        assert equivalent(expr, out)

    def test_ordered_or_equal_refusals(self):
        a, b, c = self._v(1, 32), self._v(2, 32), self._v(3, 32)
        zero = self._c(0, 32)
        lt = self._bin("CmpLT", a, b, 1, signed=True)
        for eq in (
            self._bin("CmpEQ", a, c, 1),
            self._bin("CmpNE", a, b, 1),
            self._bin("CmpEQ", self._bin("Add", a, b), zero, 1),
            self._bin("CmpEQ", self._neg(self._bin("Add", a, b)), zero, 1),
            self._bin("CmpEQ", self._bin("Sub", a, b), self._c(1, 32), 1),
        ):
            assert self.le.optimize(self._bin("LogicalOr", lt, eq, 1)) is None
        assert self.le.optimize(self._bin("LogicalAnd", lt, self._bin("CmpEQ", a, b, 1), 1)) is None

    def test_complement_compare(self):
        opt = ComplementCompare(self.proj, self.proj.kb, self.m)
        a, b = self._v(1, 8), self._v(2, 8)
        na, nb, c = self._neg(a), self._neg(b), self._c(0xFA, 8)
        for op, signed in itertools.product(("CmpLT", "CmpLE", "CmpGT", "CmpGE"), (False, True)):
            for p, q in ((na, nb), (na, c), (c, nb), (self._bin("Xor", a, self._c(0xFF, 8)), nb)):
                expr = self._bin(op, p, q, 1, signed=signed)
                out = opt.optimize(expr)
                assert out is not None and out.depth < expr.depth and out.signed == signed, expr
                assert equivalent(expr, out), expr
            for p, q in ((na, b), (a, c), (c, c), (a, b)):
                assert opt.optimize(self._bin(op, p, q, 1, signed=signed)) is None
        assert opt.optimize(self._bin("Add", na, nb)) is None
        assert opt.optimize(self._bin("CmpEQ", na, nb, 1)) is None


if __name__ == "__main__":
    unittest.main()
