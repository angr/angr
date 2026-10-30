#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr import claripy
from angr.ailment import Block
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Const,
    Load,
    Register,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, Store
from angr.analyses.decompiler.vm_stack_select import fold_stack_select_loads

from .ail_equivalence import to_claripy


class TestStackSelectFold(unittest.TestCase):
    def setUp(self):
        self.m = Manager()

    def _c(self, v, bits=64):
        return Const(self.m.next_atom(), v, bits)

    def _bin(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=a.bits)

    def _svar(self, varid, off, bits=64):
        return VirtualVariable(self.m.next_atom(), varid, bits, VirtualVariableCategory.STACK, oident=off)

    def _rvar(self, varid):
        return VirtualVariable(self.m.next_atom(), varid, 64, VirtualVariableCategory.REGISTER, oident=16)

    def _assign(self, dst, src):
        return Assignment(self.m.next_atom(), dst, src)

    def _select(self, sel_mask=0xFFFFFFFFFFFFFFF7, between=()):
        """slot -72 = B; slot -80 = A; p = &slot-80; s = ~(mask | x); a = s + p; r = *a"""
        x = Register(self.m.next_atom(), 16, 64)
        sel = UnaryOp(self.m.next_atom(), "BitwiseNeg", self._bin("Or", self._c(sel_mask), x), bits=64)
        stmts = [
            self._assign(self._svar(1, -72), self._c(0xB)),
            self._assign(self._svar(2, -80), self._c(0xA)),
            self._assign(self._svar(3, -88), UnaryOp(self.m.next_atom(), "Reference", self._svar(2, -80), bits=64)),
            self._assign(self._rvar(4), sel),
            *between,
            self._assign(self._svar(5, -88), self._bin("Add", self._rvar(4), self._svar(3, -88))),
            self._assign(self._rvar(6), Load(self.m.next_atom(), self._svar(5, -88), 8, "Iend_LE")),
        ]
        block = Block(0x1000, 1, statements=stmts)
        graph = networkx.DiGraph()
        graph.add_node(block)
        return graph, block, sel

    def test_two_slot_selection_becomes_ite(self):
        graph, block, sel = self._select()
        # exactness precondition: the offset is 0 or 8 whatever x is
        s = to_claripy(sel)
        assert not claripy.Solver().satisfiable(extra_constraints=[s != 0, s != 8])
        assert fold_stack_select_loads(graph, self.m) == 1
        src = block.statements[-1].src
        assert isinstance(src, ITE)
        assert src.cond.op == "CmpEQ" and src.cond.operands[0].likes(self._rvar(4))
        assert (src.iftrue.varid, src.iffalse.varid) == (2, 1)

    def test_offset_with_more_than_two_values_stays(self):
        graph, block, _ = self._select(sel_mask=0xFFFFFFFFFFFFFFE7)
        assert fold_stack_select_loads(graph, self.m) == 0
        assert isinstance(block.statements[-1].src, Load)

    def test_store_in_between_stays(self):
        store = Store(self.m.next_atom(), Register(self.m.next_atom(), 24, 64), self._c(0), 8, "Iend_LE")
        graph, block, _ = self._select(between=(store,))
        assert fold_stack_select_loads(graph, self.m) == 0

    def test_partial_redefinition_stays(self):
        partial = self._assign(self._svar(9, -76, 32), self._c(0, 32))
        graph, block, _ = self._select(between=(partial,))
        assert fold_stack_select_loads(graph, self.m) == 0

    def test_later_full_redefinition_is_used(self):
        newer = self._assign(self._svar(9, -72), self._c(0xC))
        graph, block, _ = self._select(between=(newer,))
        assert fold_stack_select_loads(graph, self.m) == 1
        src = block.statements[-1].src
        assert (src.iftrue.varid, src.iffalse.varid) == (2, 9)


if __name__ == "__main__":
    unittest.main()
