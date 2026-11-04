from __future__ import annotations

import unittest

from angr import claripy
from angr.claripy.fp import FSORT_DOUBLE


class TestRepr(unittest.TestCase):
    """The human-readable repr, ported from pre-Rust claripy."""

    def setUp(self):
        self.x = claripy.BVS("x", 32)
        self.y = claripy.BVS("y", 32)
        self.b = claripy.BoolS("b")
        self.c = claripy.BoolS("c")
        # Symbol names carry a global counter, so they are read back rather than hardcoded.
        self.xn = self.x.args[0]
        self.yn = self.y.args[0]
        self.bn = self.b.args[0]
        self.cn = self.c.args[0]

    def test_leaves(self):
        assert repr(self.x) == f"<BV32 {self.xn}>"
        assert repr(self.b) == f"<Bool BoolS({self.bn})>"
        # Bitvector values are hexadecimal, except below 10 bits wide.
        assert repr(claripy.BVV(0x1F, 32)) == "<BV32 0x1f>"
        assert repr(claripy.BVV(3, 8)) == "<BV8 3>"
        assert repr(claripy.BVV(3, 4)) == "<BV4 3>"
        assert repr(claripy.BoolV(True)) == "<Bool True>"
        assert repr(claripy.BoolV(False)) == "<Bool False>"
        assert repr(claripy.StringV("hello")) == "<String StringV(hello)>"
        assert repr(claripy.FPV(1.0, FSORT_DOUBLE)) == "<FP64 FPV(1.0)>"
        # Floats are spelled as Python's str() spells them.
        assert repr(claripy.FPV(1e20, FSORT_DOUBLE)) == "<FP64 FPV(1e+20)>"
        # str() falls back to __repr__, as it did in claripy.
        assert str(self.x + self.y) == repr(self.x + self.y)

    def test_infix_operators(self):
        x, y, xn, yn = self.x, self.y, self.xn, self.yn
        assert repr(x + y) == f"<BV32 {xn} + {yn}>"
        assert repr(x - y) == f"<BV32 {xn} - {yn}>"
        assert repr(x * y) == f"<BV32 {xn} * {yn}>"
        assert repr(x & y) == f"<BV32 {xn} & {yn}>"
        assert repr(x | y) == f"<BV32 {xn} | {yn}>"
        assert repr(x ^ y) == f"<BV32 {xn} ^ {yn}>"
        assert repr(x << y) == f"<BV32 {xn} << {yn}>"
        assert repr(~x) == f"<BV32 ~{xn}>"
        assert repr(-x) == f"<BV32 -{xn}>"
        assert repr(x == y) == f"<Bool {xn} == {yn}>"
        assert repr(claripy.ULT(x, y)) == f"<Bool {xn} < {yn}>"
        assert repr(claripy.SGT(x, y)) == f"<Bool {xn} >s {yn}>"
        assert repr(claripy.SDiv(x, y)) == f"<BV32 {xn} /s {yn}>"
        assert repr(claripy.And(self.b, self.c)) == f"<Bool BoolS({self.bn}) && BoolS({self.cn})>"
        assert repr(claripy.Or(self.b, self.c)) == f"<Bool BoolS({self.bn}) || BoolS({self.cn})>"

    def test_operator_precedence(self):
        x, y, xn, yn = self.x, self.y, self.xn, self.yn
        # A child binding less tightly than its parent gets parenthesized.
        assert repr((x + y) * (x - y)) == f"<BV32 ({xn} + {yn}) * ({xn} - {yn})>"
        assert repr(x + y * y) == f"<BV32 {xn} + {yn} * {yn}>"
        assert repr((x | y) & x) == f"<BV32 ({xn} | {yn}) & {xn}>"
        assert repr(x * (x + y)) == f"<BV32 {xn} * ({xn} + {yn})>"
        # An equally tight right-hand child needs parentheses too.
        assert repr(x << (x << y)) == f"<BV32 {xn} << ({xn} << {yn})>"

    def test_special_forms(self):
        x, y, xn, yn = self.x, self.y, self.xn, self.yn
        assert repr(claripy.If(self.b, x, y)) == f"<BV32 if BoolS({self.bn}) then {xn} else {yn}>"
        assert repr(claripy.Not(self.b)) == f"<Bool !BoolS({self.bn})>"
        assert repr(claripy.Not(claripy.And(self.b, self.c))) == f"<Bool !(BoolS({self.bn}) && BoolS({self.cn}))>"
        assert repr(~(x + y)) == f"<BV32 ~({xn} + {yn})>"
        assert repr(claripy.Extract(15, 8, x)) == f"<BV8 {xn}[15:8]>"
        assert repr(claripy.ZeroExt(32, x)) == f"<BV64 0#32 .. {xn}>"
        assert repr(claripy.SignExt(32, x)) == f"<BV64 SignExt(32, {xn})>"
        assert repr(claripy.Concat(x, y)) == f"<BV64 {xn} .. {yn}>"
        assert repr(x.reversed) == f"<BV32 Reverse({xn})>"
        assert repr(claripy.LShR(x, y)) == f"<BV32 LShR({xn}, {yn})>"
        assert repr(claripy.RotateLeft(x, y)) == f"<BV32 RotateLeft({xn}, {yn})>"

    def test_shallow_repr(self):
        x, y, xn, yn = self.x, self.y, self.xn, self.yn
        deep = ((x + y) * (x - y)) + ((x | y) & (x ^ y))
        full = f"<BV32 ({xn} + {yn}) * ({xn} - {yn}) + (({xn} | {yn}) & ({xn} ^ {yn}))>"

        assert deep.shallow_repr(max_depth=0) == "<...>"
        assert deep.shallow_repr(max_depth=1) == "<BV32 <...> + <...>>"
        assert deep.shallow_repr(max_depth=2) == "<BV32 <...> * <...> + (<...> & <...>)>"
        assert deep.shallow_repr(max_depth=None) == full
        # The default depth of 8 covers this expression.
        assert deep.shallow_repr() == full
        assert repr(deep) == full

        # explicit_length annotates bitvector values with their width.
        assert (x + claripy.BVV(0x1F, 32)).shallow_repr(explicit_length=True) == f"<BV32 {xn} + 0x1f#32>"

        # details=1 spells out operations, details=2 leaves as well.
        assert (x + y).shallow_repr(details=1) == f"<BV32 __add__({xn}, {yn})>"
        assert (x + y).shallow_repr(details=2) == f"<BV32 __add__(BVS({xn}, 32), BVS({yn}, 32))>"
        assert (x + y).dbg_repr() == f"<BV32 __add__(BVS({xn}, 32), BVS({yn}, 32))>"
        assert claripy.BVV(0x1F, 32).shallow_repr(details=2) == "<BV32 BVV(31, 32)>"

    def test_smtlib(self):
        x, y, xn, yn = self.x, self.y, self.xn, self.yn
        assert x.smtlib() == xn
        assert (x + y).smtlib() == f"(bvadd {xn} {yn})"
        assert claripy.BVV(0x1F, 32).smtlib() == "(_ bv31 32)"
        assert claripy.If(x == y, x, y).smtlib() == f"(ite (= {xn} {yn}) {xn} {yn})"
        assert claripy.ULT(x, y).smtlib() == f"(bvult {xn} {yn})"
        assert claripy.Extract(15, 8, x).smtlib() == f"((_ extract 15 8) {xn})"

        # max_depth elides deeper children.
        neg = -(x + y)
        assert neg.smtlib() == f"(bvneg (bvadd {xn} {yn}))"
        assert neg.smtlib(0) == "(bvneg ...)"
        assert neg.smtlib(1) == "(bvneg (bvadd ... ...))"


if __name__ == "__main__":
    unittest.main()
