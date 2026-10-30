#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import BinaryOp, Const, Register
from angr.ailment.manager import Manager
from angr.analyses.decompiler.peephole_optimizations import BinaryOpCanonicalization
from angr.analyses.decompiler.variable_map import VariableMap
from angr.sim_variable import SimConstantVariable


def _nodes(expr, out):
    out.append(expr)
    for op in getattr(expr, "operands", None) or ():
        _nodes(op, out)
    return out


class TestBinaryOpCanonicalization(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.m = Manager()
        self.opt = BinaryOpCanonicalization(self.proj, self.proj.kb, self.m)

    def _c(self, v):
        return Const(self.m.next_atom(), v, 64)

    def _reg(self, off):
        return Register(self.m.next_atom(), off, 64)

    def _add(self, a, b):
        return BinaryOp(self.m.next_atom(), "Add", [a, b], False, bits=64)

    def test_only_the_root_keeps_the_idx(self):
        # (x + 6327401) + (577907475 + y)  ->  (x + y) + 584234876
        x, y = self._reg(16), self._reg(24)
        expr = self._add(self._add(x, self._c(6327401)), self._add(self._c(577907475), y))
        r = self.opt.optimize(expr)
        assert r is not None
        assert r.op == "Add" and isinstance(r.operands[1], Const) and r.operands[1].value == 584234876
        assert r.idx == expr.idx
        idxs = [n.idx for n in _nodes(r, [])]
        assert len(idxs) == len(set(idxs)), idxs

    def test_folded_constant_does_not_name_the_expression(self):
        x, y = self._reg(16), self._reg(24)
        expr = self._add(self._add(x, self._c(6327401)), self._add(self._c(577907475), y))
        r = self.opt.optimize(expr)
        const = r.operands[1]
        vm = VariableMap()
        vm.set_variable(const, SimConstantVariable(8, ident="ic_5", value=const.value))
        # the codegen renders an expression mapped to a variable as that variable (&ic_5)
        assert vm.variable(r) is None
        assert vm.variable(const) is not None

    def test_constant_variable_ignored_on_shared_idx(self):
        c = Const(5, 584234876, 64)
        b = BinaryOp(5, "Add", [self._reg(16), c], False, bits=64)
        vm = VariableMap()
        vm.set_variable(c, SimConstantVariable(8, ident="ic_5", value=584234876))
        assert vm.variable(b) is None
        assert vm.variable(c) is not None


if __name__ == "__main__":
    unittest.main()
