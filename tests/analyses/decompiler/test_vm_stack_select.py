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
    Call,
    Const,
    Load,
    Phi,
    Register,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, Jump, SideEffectStatement, Store
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


def _single(block):
    graph = networkx.DiGraph()
    graph.add_node(block)
    return graph


class TestStackSelectFoldAcrossBlocks(unittest.TestCase):
    """Slot definitions, the address and the load in different blocks (a VM handler split at junk branches)."""

    def setUp(self):
        self.m = Manager()

    def _c(self, v, bits=64):
        return Const(self.m.next_atom(), v, bits)

    def _bin(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=a.bits)

    def _svar(self, varid, off, bits=64):
        return VirtualVariable(self.m.next_atom(), varid, bits, VirtualVariableCategory.STACK, oident=off)

    def _rvar(self, varid, off=16):
        return VirtualVariable(self.m.next_atom(), varid, 64, VirtualVariableCategory.REGISTER, oident=off)

    def _assign(self, dst, src):
        return Assignment(self.m.next_atom(), dst, src)

    def _jump(self, target):
        return Jump(self.m.next_atom(), self._c(target))

    def _sel(self):
        x = Register(self.m.next_atom(), 16, 64)
        return UnaryOp(self.m.next_atom(), "BitwiseNeg", self._bin("Or", self._c(0xFFFFFFFFFFFFFFF7), x), bits=64)

    def _slots(self):
        """slot -72 = B; slot -80 = A; s = sel (0 or 8)"""
        return [
            self._assign(self._svar(1, -72), self._c(0xB)),
            self._assign(self._svar(2, -80), self._c(0xA)),
            self._assign(self._rvar(4), self._sel()),
        ]

    def _load(self, addr):
        return self._assign(self._rvar(6, 24), Load(self.m.next_atom(), addr, 8, "Iend_LE"))

    def _addr(self):
        # &slot-88 + 8 + s: the constant is part of the address
        ref = UnaryOp(self.m.next_atom(), "Reference", self._svar(7, -88), bits=64)
        return self._bin("Add", self._bin("Add", ref, self._c(8)), self._rvar(4))

    @staticmethod
    def _graph(*edges):
        graph = networkx.DiGraph()
        graph.add_edges_from(edges)
        return graph

    def _check_folded(self, block):
        src = block.statements[-1].src
        assert isinstance(src, ITE)
        assert src.cond.op == "CmpEQ" and src.cond.operands[0].likes(self._rvar(4))
        assert (src.iftrue.varid, src.iffalse.varid) == (2, 1)

    def test_defs_address_and_load_in_three_blocks(self):
        a = Block(0x10, 1, statements=[*self._slots(), self._jump(0x20)])
        b = Block(0x20, 1, statements=[self._assign(self._rvar(5, 32), self._addr()), self._jump(0x30)])
        c = Block(0x30, 1, statements=[self._load(self._rvar(5, 32))])
        assert fold_stack_select_loads(self._graph((a, b), (b, c)), self.m) == 1
        self._check_folded(c)

    def test_address_through_phi_of_one_expression(self):
        # junk diamond: both arms carry the same address; the join's phi is a copy of it
        a = Block(0x10, 1, statements=[*self._slots(), self._assign(self._rvar(5, 32), self._addr())])
        b1 = Block(0x20, 1, statements=[self._jump(0x40)])
        b2 = Block(0x30, 1, statements=[self._jump(0x40)])
        phi = Phi(self.m.next_atom(), 64, [((0x20, 1), self._rvar(5, 32)), ((0x30, 1), self._rvar(5, 32))])
        d = Block(0x40, 1, statements=[self._assign(self._rvar(8, 32), phi), self._load(self._rvar(8, 32))])
        assert fold_stack_select_loads(self._graph((a, b1), (a, b2), (b1, d), (b2, d)), self.m) == 1
        self._check_folded(d)

    def test_address_through_loop_phi_with_itself_on_the_back_edge(self):
        a = Block(0x10, 1, statements=[*self._slots(), self._assign(self._rvar(5, 32), self._addr())])
        phi = Phi(self.m.next_atom(), 64, [((0x10, 1), self._rvar(5, 32)), ((0x20, 1), self._rvar(8, 32))])
        h = Block(0x20, 1, statements=[self._assign(self._rvar(8, 32), phi), self._load(self._rvar(8, 32))])
        assert fold_stack_select_loads(self._graph((a, h), (h, h)), self.m) == 1
        self._check_folded(h)

    def test_pick_index_through_phi_uses_known_bits_of_every_source(self):
        # s = phi(s1, s2), each 0 or 8
        sel2 = self._sel()
        a = Block(0x10, 1, statements=[self._assign(self._svar(1, -72), self._c(0xB)), self._assign(self._svar(2, -80), self._c(0xA))])
        b1 = Block(0x20, 1, statements=[self._assign(self._rvar(10), self._sel())])
        b2 = Block(0x30, 1, statements=[self._assign(self._rvar(11), sel2)])
        phi = Phi(self.m.next_atom(), 64, [((0x20, 1), self._rvar(10)), ((0x30, 1), self._rvar(11))])
        ref = UnaryOp(self.m.next_atom(), "Reference", self._svar(2, -80), bits=64)
        d = Block(
            0x40,
            1,
            statements=[self._assign(self._rvar(4), phi), self._load(self._bin("Add", self._rvar(4), ref))],
        )
        assert fold_stack_select_loads(self._graph((a, b1), (a, b2), (b1, d), (b2, d)), self.m) == 1
        self._check_folded(d)

    def test_long_definition_chain(self):
        # a VM stack pointer: thousands of p_i = p_(i-1) + c - c, each also read twice (no exponential walk)
        stmts = [*self._slots()]
        ref = UnaryOp(self.m.next_atom(), "Reference", self._svar(2, -80), bits=64)
        stmts.append(self._assign(self._rvar(100, 48), ref))
        for i in range(101, 3101):
            prev = self._rvar(i - 1, 48)
            stmts.append(self._assign(self._rvar(i, 48), self._bin("Sub", self._bin("Add", prev, self._c(8)), self._c(8))))
        stmts.append(self._load(self._bin("Add", self._rvar(3100, 48), self._rvar(4))))
        block = Block(0x10, 1, statements=stmts)
        assert fold_stack_select_loads(_single(block), self.m) == 1
        self._check_folded(block)

    def test_known_constant_index_reads_the_one_slot(self):
        # the index is 8 whatever x is: (x | 8) & 8, through a definition in another block
        x = Register(self.m.next_atom(), 16, 64)
        idx = self._bin("And", self._bin("Or", x, self._c(8)), self._c(8))
        a = Block(0x10, 1, statements=[*self._slots()[:2], self._assign(self._rvar(4), idx), self._jump(0x20)])
        ref = UnaryOp(self.m.next_atom(), "Reference", self._svar(2, -80), bits=64)
        b = Block(0x20, 1, statements=[self._load(self._bin("Add", ref, self._rvar(4)))])
        assert fold_stack_select_loads(self._graph((a, b)), self.m) == 1
        src = b.statements[-1].src
        assert isinstance(src, VirtualVariable) and src.varid == 1

    def _diamond(self, arm1, arm2):
        a = Block(0x10, 1, statements=[*self._slots()])
        b1 = Block(0x20, 1, statements=[*arm1, self._jump(0x40)])
        b2 = Block(0x30, 1, statements=[*arm2, self._jump(0x40)])
        d = Block(0x40, 1, statements=[self._load(self._addr())])
        return self._graph((a, b1), (a, b2), (b1, d), (b2, d)), d

    def test_pure_flag_helper_in_between_folds(self):
        cf = Call(self.m.next_atom(), "__CFADD__", args=[self._c(1), self._c(2)], bits=8)
        graph, d = self._diamond([self._assign(self._rvar(12, 40), cf)], [])
        assert fold_stack_select_loads(graph, self.m) == 1
        self._check_folded(d)

    def test_slot_redefined_on_one_path_stays(self):
        graph, d = self._diamond([self._assign(self._svar(9, -72), self._c(0xC))], [])
        assert fold_stack_select_loads(graph, self.m) == 0
        assert isinstance(d.statements[-1].src, Load)

    def test_store_on_one_path_stays(self):
        store = Store(self.m.next_atom(), Register(self.m.next_atom(), 24, 64), self._c(0), 8, "Iend_LE")
        graph, _ = self._diamond([store], [])
        assert fold_stack_select_loads(graph, self.m) == 0

    def test_call_on_one_path_stays(self):
        call = SideEffectStatement(self.m.next_atom(), Call(self.m.next_atom(), self._c(0x1000), args=[]))
        graph, _ = self._diamond([], [call])
        assert fold_stack_select_loads(graph, self.m) == 0

    def test_path_from_function_entry_without_the_slot_stays(self):
        # the load's block is also reached from an entry block that defines nothing
        a = Block(0x10, 1, statements=[*self._slots(), self._jump(0x40)])
        e = Block(0x08, 1, statements=[self._assign(self._rvar(4), self._sel()), self._jump(0x40)])
        d = Block(0x40, 1, statements=[self._load(self._addr())])
        assert fold_stack_select_loads(self._graph((e, a), (a, d), (e, d)), self.m) == 0

    def test_slot_redefined_after_the_load_around_a_loop_stays(self):
        a = Block(0x10, 1, statements=[*self._slots()])
        h = Block(
            0x20,
            1,
            statements=[self._load(self._addr()), self._assign(self._svar(9, -72), self._c(0xC))],
        )
        assert fold_stack_select_loads(self._graph((a, h), (h, h)), self.m) == 0


if __name__ == "__main__":
    unittest.main()
