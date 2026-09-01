#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import claripy

import angr
from angr.ailment.expression import BinaryOp, Call, Const, Convert, Register
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import EXPR_OPTS, AndMaskPruning
from angr.analyses.decompiler.peephole_optimizations.and_mask_pruning import bit_support


def _to_claripy(expr):
    if isinstance(expr, Const):
        return claripy.BVV(expr.value_int, expr.bits)
    if isinstance(expr, Register):
        return claripy.BVS(f"r{expr.reg_offset}", expr.bits, explicit_name=True)
    if isinstance(expr, Convert):
        v = _to_claripy(expr.operand)
        if expr.to_bits == expr.from_bits:
            return v
        if expr.to_bits < expr.from_bits:
            return v[expr.to_bits - 1 : 0]
        extend = v.sign_extend if expr.is_signed else v.zero_extend
        return extend(expr.to_bits - expr.from_bits)
    if isinstance(expr, BinaryOp):
        a, b = _to_claripy(expr.operands[0]), _to_claripy(expr.operands[1])
        if expr.op in ("Shl", "Shr"):
            b = b.zero_extend(a.size() - b.size()) if b.size() < a.size() else b[a.size() - 1 : 0]
            return a << b if expr.op == "Shl" else claripy.LShR(a, b)
        if expr.op == "CmpEQ":
            return claripy.If(a == b, claripy.BVV(1, 1), claripy.BVV(0, 1))
        return {"And": lambda: a & b, "Or": lambda: a | b, "Xor": lambda: a ^ b}[expr.op]()
    raise NotImplementedError(type(expr))


class TestAndMaskPruning(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()
        self.opt = AndMaskPruning(self.proj, self.proj.kb, self.m)

    def _const(self, v, bits=64):
        return Const(self.m.next_atom(), v, bits)

    def _and(self, a, b):
        return BinaryOp(self.m.next_atom(), "And", [a, b], False, bits=a.bits)

    def _or(self, a, b):
        return BinaryOp(self.m.next_atom(), "Or", [a, b], False, bits=a.bits)

    def _shl(self, a, n):
        return BinaryOp(self.m.next_atom(), "Shl", [a, self._const(n, 8)], False, bits=a.bits)

    def _flag_bit(self, reg_offset, shift):
        """A single positioned flag bit, the shape the rflags_all rewriter emits."""
        bit = BinaryOp(
            self.m.next_atom(), "CmpEQ", [Register(self.m.next_atom(), reg_offset, 64), self._const(0)], False
        )
        return self._shl(Convert(self.m.next_atom(), 1, 64, False, bit), shift)

    def test_registered(self):
        assert AndMaskPruning in EXPR_OPTS

    def test_bit_support_of_a_positioned_flag_bit(self):
        assert bit_support(self._flag_bit(16, 6)) == 1 << 6

    def test_bit_support_of_nested_masks(self):
        x = Register(self.m.next_atom(), 16, 64)
        assert bit_support(self._and(self._and(x, self._const(0xFF)), self._const(0x0F))) == 0x0F

    def test_merges_nested_masks(self):
        x = Register(self.m.next_atom(), 16, 64)
        out = self.opt.optimize(self._and(self._and(x, self._const(0xFFFFF7EA)), self._const(64)))
        assert isinstance(out, BinaryOp) and out.op == "And"
        assert out.operands[0].likes(x)
        assert out.operands[1].value_int == 64

    def test_drops_the_disjunct_the_mask_kills(self):
        # (ZF<<6 | SF<<7) & 0x40  ==>  (ZF<<6) & 0x40
        zf, sf = self._flag_bit(16, 6), self._flag_bit(24, 7)
        out = self.opt.optimize(self._and(self._or(zf, sf), self._const(64)))
        assert isinstance(out, BinaryOp) and out.op == "And"
        assert out.operands[0].likes(zf)

    def test_handles_the_constant_on_either_side(self):
        zf, sf = self._flag_bit(16, 6), self._flag_bit(24, 7)
        flipped = BinaryOp(self.m.next_atom(), "And", [self._const(64), self._or(zf, sf)], False, bits=64)
        out = self.opt.optimize(flipped)
        assert isinstance(out, BinaryOp) and out.operands[0].likes(zf)

    def test_leaves_an_impure_disjunct_alone(self):
        # dropping a disjunct that contains a call would drop the call
        call = self._shl(Call(self.m.next_atom(), "f", args=[], bits=64), 7)
        zf = self._flag_bit(16, 6)
        assert self.opt.optimize(self._and(self._or(zf, call), self._const(64))) is None

    def test_leaves_unmaskable_expressions_alone(self):
        x = Register(self.m.next_atom(), 16, 64)
        y = Register(self.m.next_atom(), 24, 64)
        assert self.opt.optimize(self._and(self._or(x, y), self._const(64))) is None
        assert self.opt.optimize(self._and(x, y)) is None

    def test_rewrites_are_equivalent(self):
        # the VM flag-merging idiom: take some bits from one packed word and the rest from another
        pf, zf, sf = self._flag_bit(16, 2), self._flag_bit(24, 6), self._flag_bit(32, 7)
        other = Register(self.m.next_atom(), 40, 64)
        merged = self._or(
            self._and(self._or(self._or(pf, zf), sf), self._const(0xFFFFFFFFFFFFF7EA)),
            self._and(other, self._const(2069)),
        )
        for mask in (1, 4, 64, 128, 0x800, 0x8D5, 2069, 0xFFFFFFFFFFFFF7EA):
            expr = self._and(merged, self._const(mask))
            out = self.opt.optimize(expr)
            if out is None:
                continue
            solver = claripy.Solver()
            solver.add(_to_claripy(expr) != _to_claripy(out))
            assert not solver.satisfiable(), f"mask {mask:#x}: rewrite is not equivalent"

    def test_reaches_a_fixed_point(self):
        pf, zf, sf = self._flag_bit(16, 2), self._flag_bit(24, 6), self._flag_bit(32, 7)
        expr = self._and(self._and(self._or(self._or(pf, zf), sf), self._const(0xF7EA)), self._const(64))
        for _ in range(16):
            out = self.opt.optimize(expr)
            if out is None:
                break
            expr = out
        else:
            raise AssertionError("AndMaskPruning did not converge")


if __name__ == "__main__":
    unittest.main()
