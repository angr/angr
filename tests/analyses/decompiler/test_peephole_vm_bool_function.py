#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import claripy
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Const,
    Load,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.peephole_optimizations import SingleBoolToITE
from angr.analyses.decompiler.peephole_optimizations.vm_bool_function import _Evaluator
from angr.utils.ail import BlockDefs
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _to_claripy(expr):
    if isinstance(expr, Const):
        return claripy.BVV(expr.value_int, expr.bits)
    if isinstance(expr, VirtualVariable):
        return claripy.BVS(f"v{expr.varid}", expr.bits, explicit_name=True)
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
        return {"And": lambda: a & b, "Or": lambda: a | b, "Add": lambda: a + b, "Mul": lambda: a * b}[expr.op]()
    raise NotImplementedError(type(expr))


class TestSingleBoolToITE(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "x86")
        self.m = Manager()
        self.opt = SingleBoolToITE(self.proj, self.proj.kb, self.m)

    def c(self, v, bits=32):
        return Const(self.m.next_atom(), v, bits)

    def reg(self, varid=9, bits=32):
        # a variable with no definition in sight
        return VirtualVariable(self.m.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=16)

    def b(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=a.bits)

    def neg(self, a):
        return UnaryOp(self.m.next_atom(), "BitwiseNeg", a, bits=a.bits)

    def vvar(self, varid, bits=32):
        return VirtualVariable(self.m.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=8)

    def bit6(self, flags, inverted=True):
        x = self.neg(flags) if inverted else flags
        return self.b("Shr", self.b("And", x, self.c(64)), self.c(6, 8))

    def mba_select(self, flags):
        # VMProtect ultra's next-key address: ~f bit 6 selects between 0x444504 and 0x44de7e (+ the image delta)
        m = self.b("Add", self.c(0xFFFFFFFF), self.bit6(flags))
        first = self.b("Or", self.neg(self.b("Or", self.neg(m), self.c(0xFFBBBAFB))), self.b("And", m, self.c(4474116)))
        second = self.b(
            "And",
            self.b("And", self.b("And", self.neg(self.b("Or", m, self.c(0xFFBB2181))), self.neg(m)), self.neg(m)),
            self.c(4513406),
        )
        return self.b("Add", self.b("Add", first, second), self.c(0xF0000))

    def equivalent(self, a, b):
        s = claripy.Solver()
        return not s.satisfiable(extra_constraints=[_to_claripy(a) != _to_claripy(b)])

    def as_ite(self, expr, block_defs=None):
        """The value as ``cond ? v1 : v0``, as the optimizer sees it."""
        evaluator = _Evaluator(self.opt, block_defs)
        atom, v0, v1 = evaluator.evaluate(expr, block_defs.tmps if block_defs is not None else None)
        return ITE(self.m.next_atom(), self.opt._condition(atom), self.c(v1, expr.bits), self.c(v0, expr.bits))

    def test_mba_select_is_an_ite(self):
        expr = self.mba_select(self.reg())
        ite = self.as_ite(expr)
        assert {ite.iftrue.value_int, ite.iffalse.value_int} == {0x534504, 0x53DE7E}
        assert self.equivalent(expr, ite)
        # arithmetic stays as it is until it ends in a load or a condition
        assert self.opt.optimize(expr) is None

    def test_through_variable_definitions(self):
        f = self.reg()
        defs = BlockDefs(
            [
                Assignment(self.m.next_atom(), self.vvar(1), f),
                Assignment(
                    self.m.next_atom(), self.vvar(2), self.b("Add", self.c(0xFFFFFFFF), self.bit6(self.vvar(1)))
                ),
            ]
        )
        expr = self.b("And", self.neg(self.vvar(2)), self.c(0x1234))
        out = self.as_ite(expr, block_defs=defs)
        # ~(bit - 1) & 0x1234 is 0x1234 when bit 6 of ~f is set, i.e. bit 6 of f is clear
        inlined = self.b("And", self.neg(self.b("Add", self.c(0xFFFFFFFF), self.bit6(self.vvar(1)))), self.c(0x1234))
        assert self.equivalent(inlined, out)

    def test_comparison_of_a_selected_value_is_the_condition(self):
        expr = BinaryOp(self.m.next_atom(), "CmpEQ", [self.mba_select(self.reg()), self.c(0x534504)], False, bits=1)
        out = self.opt.optimize(expr)
        assert out is not None and out.bits == 1
        assert self.equivalent(expr, out)

    def test_two_booleans_are_left_alone(self):
        f = self.reg()
        expr = self.b("Add", self.bit6(f), self.b("Shr", self.b("And", f, self.c(128)), self.c(7, 8)))
        assert self.opt.optimize(expr) is None

    def test_a_whole_value_is_left_alone(self):
        f = self.reg()
        assert self.opt.optimize(self.b("Add", self.bit6(f), f)) is None
        # the boolean on its own stays as it is
        assert self.opt.optimize(self.bit6(f)) is None

    def test_load_at_a_selected_address(self):
        proj = angr.Project(os.path.join(test_location, "armel", "decompiler", "rm"), auto_load_libs=False)
        opt = SingleBoolToITE(proj, proj.kb, self.m)
        f = self.reg()
        addr = self.b("Add", self.b("Mul", self.bit6(f, inverted=False), self.c(4)), self.c(0xA000))
        out = opt.optimize(Load(self.m.next_atom(), addr, 4, "Iend_LE"))
        expected = proj.loader.memory.unpack_word(0xA004, 4), proj.loader.memory.unpack_word(0xA000, 4)
        assert isinstance(out, ITE) and (out.iftrue.value_int, out.iffalse.value_int) == expected
        # writable memory may change: keep the load
        addr = self.b("Add", self.b("Mul", self.bit6(f, inverted=False), self.c(4)), self.c(0x21DF4))
        assert opt.optimize(Load(self.m.next_atom(), addr, 4, "Iend_LE")) is None


if __name__ == "__main__":
    unittest.main()
