#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import archinfo
import networkx

from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Insert,
    Load,
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.analyses.decompiler.stack_dead_store_eliminator import StackAddr, StackDeadStoreEliminator


class TestCanonicalFrameAddr(unittest.TestCase):
    """The rule that picks one frame address when the frame pointer merges to several."""

    @staticmethod
    def _addr(chain, offset):
        return StackAddr("sp", tuple(("add", v) for v in chain), offset)

    def test_prefers_the_least_derived_value(self):
        # The frame pointer as established, versus the same pointer after a path took an
        # adjustment: the shorter derivation is the canonical one.
        established = self._addr((-216, 8, -16, -136), -360)
        adjusted = self._addr((-216, 8, -16, -136, 152, -16, 8, -16, -136), -368)
        for addrs in ((established, adjusted), (adjusted, established)):
            assert StackDeadStoreEliminator._canonical_frame_addr(addrs) is established

    def test_ties_go_to_the_highest_offset(self):
        low = self._addr((-16,), -16)
        high = self._addr((-8,), -8)
        assert StackDeadStoreEliminator._canonical_frame_addr((low, high)) is high

    def test_a_known_offset_beats_an_opaque_one(self):
        opaque = StackAddr("sp", (("and", -16),), None)
        known = StackAddr("sp", (("add", -8),), -8)
        assert StackDeadStoreEliminator._canonical_frame_addr((opaque, known)) is known

    def test_choice_does_not_depend_on_input_order(self):
        a = self._addr((-8, 16), 8)
        b = self._addr((-8, 24), 16)
        c = self._addr((-8, 24, 8), 24)
        assert (
            StackDeadStoreEliminator._canonical_frame_addr((a, b, c))
            is StackDeadStoreEliminator._canonical_frame_addr((c, b, a))
        )


class TestFrameRegisterRewrite(unittest.TestCase):
    """The frame register itself must become a StackBaseOffset, not just the addresses."""

    @staticmethod
    def _graph():
        """``sp1 = sp0 - 224``, then a store and a load through ``sp1``."""
        arch = archinfo.ArchAMD64()
        m = ailment.Manager()

        def sp(varid):
            return VirtualVariable(m.next_atom(), varid, 64, VirtualVariableCategory.REGISTER, oident=arch.sp_offset)

        def const(value):
            return Const(m.next_atom(), value, 64)

        statements = [
            Assignment(
                m.next_atom(),
                sp(2),
                BinaryOp(m.next_atom(), "Sub", [sp(1), const(224)], False, bits=64),
                ins_addr=0x1000,
            ),
            Store(m.next_atom(), sp(2), const(1), 8, arch.memory_endness, ins_addr=0x1004),
            Assignment(
                m.next_atom(),
                VirtualVariable(m.next_atom(), 3, 64, VirtualVariableCategory.REGISTER, oident=0),
                Load(m.next_atom(), sp(2), 8, arch.memory_endness),
                ins_addr=0x1008,
            ),
        ]
        block = Block(0x1000, 12, statements=statements)
        graph = networkx.DiGraph()
        graph.add_node(block)
        return arch, m, graph, block

    def test_frame_register_definition_becomes_a_stack_base_offset(self):
        arch, m, graph, block = self._graph()
        StackDeadStoreEliminator(arch, graph, ail_manager=m).run()
        src = block.statements[0].src
        assert isinstance(src, StackBaseOffset), f"frame register still holds register arithmetic: {src}"
        assert src.offset == -224

    def test_addresses_through_the_frame_register_become_stack_base_offsets(self):
        arch, m, graph, block = self._graph()
        StackDeadStoreEliminator(arch, graph, ail_manager=m).run()
        assert isinstance(block.statements[1].addr, StackBaseOffset)
        assert isinstance(block.statements[2].src.addr, StackBaseOffset)


class TestForwardingThroughFrameSlots(unittest.TestCase):
    """A frame address kept in a frame slot (a VM register) resolves where it is loaded back."""

    def setUp(self):
        self.arch = archinfo.ArchX86()
        self.m = ailment.Manager()

    def sbo(self, off):
        return StackBaseOffset(self.m.next_atom(), 32, off)

    def const(self, v):
        return Const(self.m.next_atom(), v, 32)

    def store(self, addr, data, ins):
        return Store(self.m.next_atom(), addr, data, 4, self.arch.memory_endness, ins_addr=ins)

    def load(self, addr):
        return Load(self.m.next_atom(), addr, 4, self.arch.memory_endness)

    def add(self, a, b):
        return BinaryOp(self.m.next_atom(), "Add", [a, b], False, bits=32)

    def run_graph(self, *blocks):
        graph = networkx.DiGraph()
        for b in blocks:
            graph.add_node(b)
        for a, b in zip(blocks, blocks[1:]):
            graph.add_edge(a, b)
        sdse = StackDeadStoreEliminator(self.arch, graph, ail_manager=self.m)
        sdse.run()
        return sdse

    def use_block(self):
        # *(Load(slot) - 0x190) = 0, the shape of a VM writing a local through its frame pointer
        return Block(0x2000, 8, statements=[
            self.store(self.add(self.load(self.sbo(-0x20)), self.const(0xFFFFFE70)), self.const(0), 0x2000),
            self.read(-0x360, 0x2004),
        ])

    def read(self, off, ins):
        dst = VirtualVariable(self.m.next_atom(), 9, 32, VirtualVariableCategory.REGISTER, oident=8)
        return Assignment(self.m.next_atom(), dst, self.load(self.sbo(off)), ins_addr=ins)

    def test_address_through_slot_becomes_a_local(self):
        a = Block(0x1000, 4, statements=[self.store(self.sbo(-0x20), self.sbo(-0x1D0), 0x1000)])
        b = self.use_block()
        sdse = self.run_graph(a, b)
        addr = b.statements[0].addr
        assert isinstance(addr, StackBaseOffset) and addr.offset == -0x360, addr
        assert sdse.forwarded

    def test_call_kills_the_slot(self):
        a = Block(0x1000, 8, statements=[
            self.store(self.sbo(-0x20), self.sbo(-0x1D0), 0x1000),
            SideEffectStatement(self.m.next_atom(), Call(self.m.next_atom(), self.const(0x5000), args=[]), ins_addr=0x1004),
        ])
        b = self.use_block()
        self.run_graph(a, b)
        assert not isinstance(b.statements[0].addr, StackBaseOffset)

    def test_unresolvable_store_kills_the_slot(self):
        opaque = VirtualVariable(self.m.next_atom(), 7, 32, VirtualVariableCategory.REGISTER, oident=8)
        a = Block(0x1000, 8, statements=[
            self.store(self.sbo(-0x20), self.sbo(-0x1D0), 0x1000),
            self.store(self.add(self.sbo(-0x40), opaque), self.const(1), 0x1004),
        ])
        b = self.use_block()
        self.run_graph(a, b)
        assert not isinstance(b.statements[0].addr, StackBaseOffset)

    def test_one_path_without_a_frame_address_blocks_forwarding(self):
        entry = Block(0x1000, 4, statements=[self.store(self.sbo(-0x20), self.sbo(-0x1D0), 0x1000)])
        other = Block(0x1800, 4, statements=[self.store(self.sbo(-0x20), self.const(5), 0x1800)])
        b = self.use_block()
        graph = networkx.DiGraph()
        graph.add_edge(entry, other)
        graph.add_edge(entry, b)
        graph.add_edge(other, b)
        StackDeadStoreEliminator(self.arch, graph, ail_manager=self.m).run()
        assert not isinstance(b.statements[0].addr, StackBaseOffset)

    def test_frame_pointer_popped_from_a_slot(self):
        bp = VirtualVariable(self.m.next_atom(), 3, 32, VirtualVariableCategory.REGISTER, oident=self.arch.bp_offset)
        a = Block(0x1000, 8, statements=[
            self.store(self.sbo(-0x20), self.sbo(-0x1D0), 0x1000),
            Assignment(self.m.next_atom(), bp, self.load(self.sbo(-0x20)), ins_addr=0x1004),
        ])
        b = Block(0x2000, 8, statements=[
            self.store(self.add(bp, self.const(0xFFFFFFFC)), self.const(0), 0x2000),
            self.read(-0x1D4, 0x2004),
        ])
        self.run_graph(a, b)
        src = next(st.src for st in a.statements if isinstance(st, Assignment))
        assert isinstance(src, StackBaseOffset) and src.offset == -0x1D0, src
        assert isinstance(b.statements[0].addr, StackBaseOffset) and b.statements[0].addr.offset == -0x1D4


class TestReadsInsideOtherExpressions(unittest.TestCase):
    def test_load_inside_insert_keeps_the_store(self):
        arch = archinfo.ArchX86()
        m = ailment.Manager()

        def sbo(off):
            return StackBaseOffset(m.next_atom(), 32, off)

        def const(v, bits=32):
            return Const(m.next_atom(), v, bits)

        def vvar(varid, bits=64):
            return VirtualVariable(m.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=8)

        stored = Store(m.next_atom(), sbo(-0x10), const(1), 4, arch.memory_endness, ins_addr=0x1000)
        read = Assignment(
            m.next_atom(),
            vvar(2),
            Insert(m.next_atom(), vvar(1), const(0), Load(m.next_atom(), sbo(-0x10), 4, arch.memory_endness),
                   arch.memory_endness),
            ins_addr=0x1004,
        )
        block = Block(0x1000, 8, statements=[stored, read])
        graph = networkx.DiGraph()
        graph.add_node(block)
        StackDeadStoreEliminator(arch, graph, ail_manager=m).run()
        assert block.statements[0] is stored


if __name__ == "__main__":
    unittest.main()
