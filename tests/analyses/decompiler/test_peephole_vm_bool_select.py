#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import claripy
from angr.ailment.expression import ITE, BinaryOp, Const, Convert, Extract, Load, Register, UnaryOp
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.block_simplifier import BlockSimplifier
from angr.analyses.decompiler.peephole_optimizations import (
    AndMaskPruning,
    BoolMulXor,
    BoolPlusConstToITE,
    DisjointAddToOr,
    ITEConstArms,
    MulPow2ShrCancel,
    RemoveRedundantNegations,
    XorSimplifications,
)
from angr.code_location import AILCodeLocation
from tests.common import bin_location

from .ail_equivalence import equivalent

test_location = os.path.join(bin_location, "tests")


def _to_claripy(expr):
    """Translate the subset of AIL these tests build into claripy, so rewrites can be checked for equivalence."""
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
        return (v.sign_extend if expr.is_signed else v.zero_extend)(expr.to_bits - expr.from_bits)
    if isinstance(expr, UnaryOp):
        v = _to_claripy(expr.operand)
        return {"BitwiseNeg": lambda: ~v, "Neg": lambda: -v, "Not": lambda: v ^ 1}[expr.op]()
    if isinstance(expr, ITE):
        return claripy.If(_to_claripy(expr.cond) == 1, _to_claripy(expr.iftrue), _to_claripy(expr.iffalse))
    if isinstance(expr, BinaryOp):
        a, b = _to_claripy(expr.operands[0]), _to_claripy(expr.operands[1])
        if expr.op in ("Shl", "Shr"):
            b = b.zero_extend(a.size() - b.size()) if b.size() < a.size() else b[a.size() - 1 : 0]
            return a << b if expr.op == "Shl" else claripy.LShR(a, b)
        if expr.op in ("CmpEQ", "CmpNE"):
            hit = a == b if expr.op == "CmpEQ" else a != b
            return claripy.If(hit, claripy.BVV(1, 1), claripy.BVV(0, 1))
        return {
            "And": lambda: a & b,
            "Or": lambda: a | b,
            "Xor": lambda: a ^ b,
            "Add": lambda: a + b,
            "Mul": lambda: a * b,
        }[expr.op]()
    raise NotImplementedError(type(expr))


def _equivalent(a, b) -> bool:
    s = claripy.Solver()
    return not s.satisfiable(extra_constraints=[_to_claripy(a) != _to_claripy(b)])


class TestVMBoolSelect(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()

    def _const(self, v, bits=64):
        return Const(self.m.next_atom(), v, bits)

    def _reg(self, off, bits=64):
        return Register(self.m.next_atom(), off, bits)

    def _bin(self, op, a, b, bits=None):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=bits or a.bits)

    def _not(self, a):
        return UnaryOp(self.m.next_atom(), "BitwiseNeg", a, bits=a.bits)

    def _flag(self, cond, value, bits=64):
        # Conv(1->64, cond) * value: one flag of a packed flags word
        return self._bin("Mul", Convert(self.m.next_atom(), 1, bits, False, cond), self._const(value, bits))

    def _cmp(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=1)

    def _vvar(self, varid, bits=64):
        from angr.ailment.expression import VirtualVariable, VirtualVariableCategory

        return VirtualVariable(self.m.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=16)

    def _ite(self, cond, a, b, bits=64):
        return ITE(self.m.next_atom(), cond, self._const(a, bits), self._const(b, bits))

    def test_complement_drops_or_terms_outside_the_mask(self):
        opt = AndMaskPruning(self.proj, self.proj.kb, self.m)
        zf = self._cmp("CmpEQ", self._reg(16), self._const(5))
        flags = self._bin("Or", self._bin("Or", self._flag(self._cmp("CmpEQ", self._reg(24), self._const(0)), 4), self._flag(zf, 64)), self._flag(self._cmp("CmpNE", self._reg(32), self._const(0)), 128))
        expr = self._bin("And", self._not(self._bin("And", self._const(0xFFFFFFFFFFFFF7EA), flags)), self._const(64))
        out = opt.optimize(expr)
        # 64 & ~(mask & flags) with 64 inside the mask: the zero flag is the only survivor, complemented
        assert isinstance(out, BinaryOp) and out.op == "Mul"
        conv = out.operands[0]
        assert isinstance(conv, Convert) and isinstance(conv.operand, UnaryOp) and conv.operand.op == "Not"
        assert conv.operand.operand.likes(zf)
        assert _equivalent(expr, out)

    def test_complement_of_unrelated_bits_is_the_mask(self):
        opt = AndMaskPruning(self.proj, self.proj.kb, self.m)
        expr = self._bin("And", self._not(self._bin("And", self._reg(16), self._const(0x815))), self._const(64))
        out = opt.optimize(expr)
        assert isinstance(out, Const) and out.value_int == 64
        assert _equivalent(expr, out)

    def test_complement_prunes_under_xor(self):
        opt = AndMaskPruning(self.proj, self.proj.kb, self.m)
        zf1 = self._cmp("CmpEQ", self._reg(16), self._const(0))
        zf2 = self._cmp("CmpEQ", self._reg(24), self._const(0))
        a = self._bin("Or", self._const(4), self._flag(zf1, 64))
        b = self._bin("Or", self._flag(zf2, 64), self._flag(self._cmp("CmpNE", self._reg(32), self._const(0)), 128))
        expr = self._bin("And", self._not(self._bin("Xor", a, b)), self._const(64))
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "And"
        inner = out.operands[0].operand
        assert inner.op == "Xor" and inner.operands[0].likes(self._flag(zf1, 64)) and inner.operands[1].likes(self._flag(zf2, 64))
        assert _equivalent(expr, out)

    def test_bool_mul_xor(self):
        opt = BoolMulXor(self.proj, self.proj.kb, self.m)
        c1 = self._cmp("CmpEQ", self._reg(16), self._const(0))
        c2 = self._cmp("CmpEQ", self._reg(24), self._const(0))
        expr = self._bin("Xor", self._flag(c1, 64), self._flag(c2, 64))
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "Mul" and out.operands[0].operand.op == "Xor"
        assert _equivalent(expr, out)
        assert opt.optimize(self._bin("Xor", self._flag(c1, 64), self._flag(c2, 128))) is None

    def test_mba_xor(self):
        opt = XorSimplifications(self.proj, self.proj.kb, self.m)
        a, b = self._reg(16), self._reg(24)
        conj = self._bin("And", self._bin("Or", a, b), self._bin("Or", self._not(b), self._not(a)))
        out = opt.optimize(conj)
        assert isinstance(out, BinaryOp) and out.op == "Xor" and _equivalent(conj, out)
        disj = self._bin("Or", self._bin("And", self._not(b), a), self._bin("And", self._not(a), b))
        out = opt.optimize(disj)
        assert isinstance(out, BinaryOp) and out.op == "Xor" and _equivalent(disj, out)
        assert opt.optimize(self._bin("And", self._bin("Or", a, b), self._bin("Or", self._not(b), a))) is None

    def test_demorgan_with_constant(self):
        opt = RemoveRedundantNegations(self.proj, self.proj.kb, self.m)
        y = self._bin("And", self._reg(16), self._reg(24))
        expr = self._not(self._bin("Or", self._const(0xFFFFFFFFFFFFFFBF), y))
        out = opt.optimize(expr)
        assert isinstance(out, BinaryOp) and out.op == "And"
        assert any(isinstance(o, Const) and o.value_int == 64 for o in out.operands)
        assert _equivalent(expr, out)
        # no constant: unchanged
        assert opt.optimize(self._not(self._bin("Or", self._reg(32), y))) is None

    def test_depth_exempt_replacement(self):
        # a 16-deep definition folds into its use only when the (location, varid) is exempt
        deep = self._reg(16)
        for i in range(16):
            deep = self._bin("Add", deep, self._const(i))
        vvar = self._vvar(1)
        use = Assignment(self.m.next_atom(), self._vvar(2), self._bin("Add", vvar, self._const(1)))
        from angr.ailment.block import Block

        block = Block(0x1000, 1, statements=[use])
        loc = AILCodeLocation(0x1000, None, 0)
        reps = {loc: {vvar: deep}}
        replaced, _ = BlockSimplifier.replace_and_build(block, reps, self.m)
        assert not replaced
        replaced, new_block = BlockSimplifier.replace_and_build(block, reps, self.m, depth_exempt={(loc, 1)})
        assert replaced and new_block.statements[0].src.operands[0].likes(deep)

    def test_eager_idempotent_and(self):
        from angr.analyses.decompiler.peephole_optimizations import EagerEvaluation

        opt = EagerEvaluation(self.proj, self.proj.kb, self.m)
        c = self._cmp("CmpEQ", self._reg(16), self._const(5))
        assert opt.optimize(BinaryOp(self.m.next_atom(), "LogicalAnd", [c, c], False, bits=1)).likes(c)
        x = self._bin("And", self._reg(16), self._const(0xFF))
        assert opt.optimize(self._bin("And", x, x)).likes(x)

    def test_disjoint_add_is_or(self):
        opt = DisjointAddToOr(self.proj, self.proj.kb, self.m)
        a = self._bin("And", self._reg(16), self._const(0x815))
        b = self._bin("And", self._reg(24), self._const(0xFFFFFFFFFFFFF7EA))
        out = opt.optimize(self._bin("Add", a, b))
        assert isinstance(out, BinaryOp) and out.op == "Or"
        assert _equivalent(self._bin("Add", a, b), out)
        assert opt.optimize(self._bin("Add", a, self._bin("And", self._reg(24), self._const(0x1)))) is None

    def test_mul_pow2_shr_cancels(self):
        opt = MulPow2ShrCancel(self.proj, self.proj.kb, self.m)
        flag = self._flag(self._cmp("CmpEQ", self._reg(16), self._const(5)), 64)
        expr = self._bin("Shr", flag, self._const(6, 8))
        out = opt.optimize(expr)
        assert out.likes(flag.operands[0])
        assert _equivalent(expr, out)
        # a full-width operand may lose bits to the multiplication
        assert opt.optimize(self._bin("Shr", self._bin("Mul", self._reg(16), self._const(64)), self._const(6, 8))) is None

    def test_bool_plus_const_is_ite(self):
        opt = BoolPlusConstToITE(self.proj, self.proj.kb, self.m)
        cond = self._cmp("CmpNE", self._reg(16), self._const(5))
        expr = self._bin("Add", self._const(0xFFFFFFFFFFFFFFFF), Convert(self.m.next_atom(), 1, 64, False, cond))
        out = opt.optimize(expr)
        assert isinstance(out, ITE) and out.cond.likes(cond)
        assert out.iftrue.value_int == 0 and out.iffalse.value_int == 0xFFFFFFFFFFFFFFFF
        assert _equivalent(expr, out)

    def test_ite_const_arms_fold(self):
        opt = ITEConstArms(self.proj, self.proj.kb, self.m)
        cond = self._cmp("CmpNE", self._reg(16), self._const(5))
        sel = self._ite(cond, 0, 0xFFFFFFFFFFFFFFFF)
        for expr, iftrue, iffalse in (
            (self._bin("And", sel, self._const(0x1400A0000)), 0, 0x1400A0000),
            (self._bin("Or", self._const(0xFFFFFFFEBFF5F550), sel), 0xFFFFFFFEBFF5F550, 0xFFFFFFFFFFFFFFFF),
            (self._not(sel), 0xFFFFFFFFFFFFFFFF, 0),
            (self._bin("Rol", self._ite(cond, 0x8000000000000001, 3), self._const(1, 8)), 3, 6),
            (self._bin("Add", self._ite(cond, 0, 0x1400A0000), self._ite(cond, 0x1400A0AAF, 0)), 0x1400A0AAF, 0x1400A0000),
            (Convert(self.m.next_atom(), 64, 32, False, self._ite(cond, 0x1400A0AAF, 0x1400A0000)), 0x400A0AAF, 0x400A0000),
            (Extract(self.m.next_atom(), 32, self._ite(cond, 0x1400A0AAF, 0x1400A0000), self._const(0), "Iend_LE"), 0x400A0AAF, 0x400A0000),
            # the offset counts bytes
            (Extract(self.m.next_atom(), 16, self._ite(cond, 0x1400A0AAF, 0x1400A0000), self._const(2), "Iend_LE"), 0x400A, 0x400A),
            (Extract(self.m.next_atom(), 8, self._ite(cond, 0x1400A0AAF, 0x1400A0000), self._const(1), "Iend_LE"), 0x0A, 0x00),
        ):
            out = opt.optimize(expr)
            assert isinstance(out, ITE) and out.cond.likes(cond), expr
            assert (out.iftrue.value_int, out.iffalse.value_int) == (iftrue, iffalse), expr
            assert equivalent(expr, out), expr
        # different conditions do not fold
        other = self._cmp("CmpNE", self._reg(24), self._const(5))
        assert opt.optimize(self._bin("Add", self._ite(cond, 0, 1), self._ite(other, 1, 0))) is None

    def test_ite_comparison_becomes_the_condition(self):
        opt = ITEConstArms(self.proj, self.proj.kb, self.m)
        cond = self._cmp("CmpNE", self._reg(16), self._const(5))
        out = opt.optimize(self._cmp("CmpEQ", self._ite(cond, 157038, 0xFFFB1458, 32), self._const(157038, 32)))
        assert isinstance(out, ITE) and out.bits == 1
        assert (out.iftrue.value_int, out.iffalse.value_int) == (1, 0)
        assert opt.optimize(out).likes(cond)
        flipped = opt.optimize(self._cmp("CmpNE", self._ite(cond, 157038, 0xFFFB1458, 32), self._const(157038, 32)))
        negated = opt.optimize(flipped)
        assert isinstance(negated, UnaryOp) and negated.op == "Not" and negated.operand.likes(cond)

    def test_ite_load_from_read_only_memory(self):
        proj = angr.Project(os.path.join(test_location, "armel", "decompiler", "rm"), auto_load_libs=False)
        opt = ITEConstArms(proj, proj.kb, self.m)
        cond = self._cmp("CmpNE", self._reg(16, 32), self._const(5, 32))
        expected = proj.loader.memory.unpack_word(0xA000, 4), proj.loader.memory.unpack_word(0xA004, 4)
        out = opt.optimize(Load(self.m.next_atom(), self._ite(cond, 0xA000, 0xA004, 32), 4, "Iend_LE"))
        assert isinstance(out, ITE) and (out.iftrue.value_int, out.iffalse.value_int) == expected
        # one arm in writable memory: keep the load
        assert opt.optimize(Load(self.m.next_atom(), self._ite(cond, 0xA000, 0x21DF4, 32), 4, "Iend_LE")) is None


if __name__ == "__main__":
    unittest.main()
