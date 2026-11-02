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
    UnaryOp,
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
        assert StackDeadStoreEliminator._canonical_frame_addr(
            (a, b, c)
        ) is StackDeadStoreEliminator._canonical_frame_addr((c, b, a))


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
        return Block(
            0x2000,
            8,
            statements=[
                self.store(self.add(self.load(self.sbo(-0x20)), self.const(0xFFFFFE70)), self.const(0), 0x2000),
                self.read(-0x360, 0x2004),
            ],
        )

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
        a = Block(
            0x1000,
            8,
            statements=[
                self.store(self.sbo(-0x20), self.sbo(-0x1D0), 0x1000),
                SideEffectStatement(
                    self.m.next_atom(), Call(self.m.next_atom(), self.const(0x5000), args=[]), ins_addr=0x1004
                ),
            ],
        )
        b = self.use_block()
        self.run_graph(a, b)
        assert not isinstance(b.statements[0].addr, StackBaseOffset)

    def test_unresolvable_store_kills_the_slot(self):
        opaque = VirtualVariable(self.m.next_atom(), 7, 32, VirtualVariableCategory.REGISTER, oident=8)
        a = Block(
            0x1000,
            8,
            statements=[
                self.store(self.sbo(-0x20), self.sbo(-0x1D0), 0x1000),
                self.store(self.add(self.sbo(-0x40), opaque), self.const(1), 0x1004),
            ],
        )
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
        a = Block(
            0x1000,
            8,
            statements=[
                self.store(self.sbo(-0x20), self.sbo(-0x1D0), 0x1000),
                Assignment(self.m.next_atom(), bp, self.load(self.sbo(-0x20)), ins_addr=0x1004),
            ],
        )
        b = Block(
            0x2000,
            8,
            statements=[
                self.store(self.add(bp, self.const(0xFFFFFFFC)), self.const(0), 0x2000),
                self.read(-0x1D4, 0x2004),
            ],
        )
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
            Insert(
                m.next_atom(),
                vvar(1),
                const(0),
                Load(m.next_atom(), sbo(-0x10), 4, arch.memory_endness),
                arch.memory_endness,
            ),
            ins_addr=0x1004,
        )
        block = Block(0x1000, 8, statements=[stored, read])
        graph = networkx.DiGraph()
        graph.add_node(block)
        StackDeadStoreEliminator(arch, graph, ail_manager=m).run()
        assert block.statements[0] is stored


class TestNegatedFrameValues(unittest.TestCase):
    """VMProtect computes ``sp - c`` as ``~(~sp + c)``, passing each step through a frame slot."""

    def setUp(self):
        self.arch = archinfo.ArchAMD64()
        self.m = ailment.Manager()

    def sbo(self, off):
        return StackBaseOffset(self.m.next_atom(), 64, off)

    def const(self, v):
        return Const(self.m.next_atom(), v, 64)

    def load(self, addr):
        return Load(self.m.next_atom(), addr, 8, self.arch.memory_endness)

    def store(self, addr, data, ins):
        return Store(self.m.next_atom(), addr, data, 8, self.arch.memory_endness, ins_addr=ins)

    def binop(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=64)

    def bnot(self, a):
        return UnaryOp(self.m.next_atom(), "BitwiseNeg", a, bits=64)

    def read(self, off, ins):
        dst = VirtualVariable(self.m.next_atom(), 9, 64, VirtualVariableCategory.REGISTER, oident=16)
        return Assignment(self.m.next_atom(), dst, self.load(self.sbo(off)), ins_addr=ins)

    def run_block(self, *stmts):
        block = Block(0x1000, 4 * len(stmts), statements=list(stmts))
        graph = networkx.DiGraph()
        graph.add_node(block)
        StackDeadStoreEliminator(self.arch, graph, ail_manager=self.m).run()
        return block

    def vm_sp_prologue(self):
        # [-8] = sp; [-16] = ~[-8] & ~[-8]; [-8] = [-16] + 56; [-8] = ~[-8] | ~[-8]
        return [
            self.store(self.sbo(-8), self.sbo(0), 0x1000),
            self.store(
                self.sbo(-16),
                self.binop("And", self.bnot(self.load(self.sbo(-8))), self.bnot(self.load(self.sbo(-8)))),
                0x1004,
            ),
            self.store(self.sbo(-8), self.binop("Add", self.load(self.sbo(-16)), self.const(56)), 0x1008),
            self.store(
                self.sbo(-8),
                self.binop("Or", self.bnot(self.load(self.sbo(-8))), self.bnot(self.load(self.sbo(-8)))),
                0x100C,
            ),
        ]

    def test_not_add_not_through_slots_is_a_frame_address(self):
        use = self.store(self.binop("Sub", self.load(self.sbo(-8)), self.const(8)), self.const(0), 0x1010)
        block = self.run_block(*self.vm_sp_prologue(), use, self.read(-64, 0x1014))
        addr = next(st.addr for st in block.statements if isinstance(st, Store) and st.tags.get("ins_addr") == 0x1010)
        assert isinstance(addr, StackBaseOffset) and addr.offset == -64, addr

    def test_negated_frame_value_is_no_address(self):
        # ~sp + 56 is not an address on the frame; it must not become a StackBaseOffset
        prologue = self.vm_sp_prologue()[:3]
        use = self.store(self.load(self.sbo(-8)), self.const(0), 0x1010)
        block = self.run_block(*prologue, use)
        addr = next(st.addr for st in block.statements if isinstance(st, Store) and st.tags.get("ins_addr") == 0x1010)
        assert not isinstance(addr, StackBaseOffset), addr

    def test_and_of_different_values_does_not_resolve(self):
        sdse = StackDeadStoreEliminator(self.arch, networkx.DiGraph(), ail_manager=self.m)
        expr = self.binop("And", self.bnot(self.sbo(-8)), self.bnot(self.sbo(-16)))
        assert sdse.resolve_value(expr) is None
        twice = self.bnot(self.binop("Add", self.bnot(self.sbo(-8)), self.const(56)))
        assert [(a.base, a.offset) for a in sdse.resolve(twice)] == [("sp", -64)]
        assert sdse.resolve(self.bnot(self.sbo(-8))) is None


class TestStackPointerAfterCall(unittest.TestCase):
    """The sp variable a call's return-address push defines is read after the callee has popped it."""

    CALL = 0x1009

    def setup(self, arch):
        self.arch = arch
        self.m = ailment.Manager()
        self.bits = arch.bits
        self.sp0 = self.sp(1)

    def sp(self, varid):
        return VirtualVariable(
            self.m.next_atom(), varid, self.bits, VirtualVariableCategory.REGISTER, oident=self.arch.sp_offset
        )

    def const(self, v):
        return Const(self.m.next_atom(), v, self.bits)

    def binop(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=self.bits)

    def run_graph(self, frame, store_at, read_at, adjustments, extra=()):
        """``sp1 = sp0 - frame; *(sp1 + store_at) = 1; sp2 = sp1 - ptr (call); call; rax = *(sp2 + read_at)``"""
        n = self.arch.bytes
        a = Block(
            0x1000,
            14,
            statements=[
                Assignment(
                    self.m.next_atom(), self.sp(2), self.binop("Sub", self.sp0, self.const(frame)), ins_addr=0x1000
                ),
                Store(
                    self.m.next_atom(),
                    self.binop("Add", self.sp(2), self.const(store_at)),
                    self.const(1),
                    n,
                    self.arch.memory_endness,
                    ins_addr=0x1004,
                ),
                Assignment(
                    self.m.next_atom(), self.sp(3), self.binop("Sub", self.sp(2), self.const(n)), ins_addr=self.CALL
                ),
                *extra,
                SideEffectStatement(
                    self.m.next_atom(), Call(self.m.next_atom(), self.const(0x5000), args=[]), ins_addr=self.CALL
                ),
            ],
        )
        dst = VirtualVariable(self.m.next_atom(), 9, self.bits, VirtualVariableCategory.REGISTER, oident=0)
        load = Load(self.m.next_atom(), self.binop("Add", self.sp(3), self.const(read_at)), n, self.arch.memory_endness)
        b = Block(0x100E, 5, statements=[Assignment(self.m.next_atom(), dst, load, ins_addr=0x100E)])
        graph = networkx.DiGraph()
        graph.add_edge(a, b)
        sdse = StackDeadStoreEliminator(self.arch, graph, ail_manager=self.m, call_sp_adjustments=adjustments)
        sdse.run()
        return sdse, a, b

    def test_post_call_frame_includes_the_return_address_pop(self):
        self.setup(archinfo.ArchAMD64())
        sdse, a, b = self.run_graph(32, 8, 8, {self.CALL: 8})
        assert sdse.removed == 0
        assert len(a.statements) == 4
        addr = b.statements[0].src.addr
        assert isinstance(addr, StackBaseOffset) and addr.offset == -24, addr
        # the push now defines sp after the call, so propagating it stays correct; SPropagator must not adjust it again
        src = a.statements[2].src
        assert isinstance(src, StackBaseOffset) and src.offset == -32, src
        assert a.statements[2].tags.get("sp_after_call") is True

    def test_post_call_frame_includes_callee_cleanup(self):
        # x86 stdcall popping one argument
        self.setup(archinfo.ArchX86())
        sdse, a, b = self.run_graph(8, 4, 0, {self.CALL: 4 + 4})
        assert sdse.removed == 0
        addr = b.statements[0].src.addr
        assert isinstance(addr, StackBaseOffset) and addr.offset == -4, addr

    def test_unknown_adjustment_leaves_post_call_frame_unresolved(self):
        self.setup(archinfo.ArchAMD64())
        for adjustments in (None, {}, {self.CALL: None}):
            sdse, a, b = self.run_graph(32, 8, 8, adjustments)
            assert sdse.removed == 0
            assert sdse.bailed_reason is not None
            assert not isinstance(b.statements[0].src.addr, StackBaseOffset)

    def test_pushed_value_read_by_the_call_instruction_is_unresolved(self):
        self.setup(archinfo.ArchAMD64())
        ret_store = Store(
            self.m.next_atom(), self.sp(3), self.const(0x100E), 8, self.arch.memory_endness, ins_addr=self.CALL
        )
        sdse, a, b = self.run_graph(32, 8, 8, {self.CALL: 8}, extra=(ret_store,))
        assert sdse.removed == 0
        assert not isinstance(b.statements[0].src.addr, StackBaseOffset)


class TestLoopCarriedFramePointer(unittest.TestCase):
    """A frame pointer merged with itself around a loop resolves when the loop leaves it unchanged."""

    def setUp(self):
        self.arch = archinfo.ArchAMD64()
        self.m = ailment.Manager()

    def sp(self, varid):
        return VirtualVariable(
            self.m.next_atom(), varid, 64, VirtualVariableCategory.REGISTER, oident=self.arch.sp_offset
        )

    def const(self, v):
        return Const(self.m.next_atom(), v, 64)

    def binop(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=64)

    def assign(self, dst, src, ins):
        return Assignment(self.m.next_atom(), dst, src, ins_addr=ins)

    def store(self, addr, value, ins, guard=None):
        return Store(
            self.m.next_atom(), addr, self.const(value), 8, self.arch.memory_endness, guard=guard, ins_addr=ins
        )

    def run_loop(self, step_back, body=()):
        """``sp2 = sp0 - 32``; loop: ``sp3 = phi(sp2, sp5); <body>; sp4 = sp3 + 8; sp5 = sp4 - step_back``"""
        a = Block(
            0x1000, 4, statements=[self.assign(self.sp(2), self.binop("Sub", self.sp(1), self.const(32)), 0x1000)]
        )
        phi = ailment.expression.Phi(self.m.next_atom(), 64, [((0x1000, 0), self.sp(2)), ((0x2000, 0), self.sp(5))])
        b = Block(
            0x2000,
            12,
            statements=[
                self.assign(self.sp(3), phi, 0x2000),
                *body,
                self.assign(self.sp(4), self.binop("Add", self.sp(3), self.const(8)), 0x2008),
                self.assign(self.sp(5), self.binop("Sub", self.sp(4), self.const(step_back)), 0x200C),
            ],
        )
        c = Block(0x3000, 1, statements=[])
        graph = networkx.DiGraph()
        graph.add_edges_from([(a, b), (b, b), (b, c)])
        sdse = StackDeadStoreEliminator(self.arch, graph, ail_manager=self.m)
        sdse.run()
        return sdse, b

    def test_balanced_loop_resolves(self):
        sdse, _ = self.run_loop(8)
        assert [(a.base, a.offset) for a in sdse._vvar_addr[3]] == [("sp", -32)]
        assert [(a.base, a.offset) for a in sdse._vvar_addr[5]] == [("sp", -32)]

    def test_loop_moving_the_frame_stays_unresolved(self):
        # sp drops by 8 per iteration: no finite set of slots, so nothing may be claimed
        sdse, _ = self.run_loop(16)
        assert 3 not in sdse._vvar_addr and 5 not in sdse._vvar_addr

    def test_overwritten_junk_in_the_loop_is_removed(self):
        junk = self.store(self.binop("Sub", self.sp(3), self.const(8)), 1, 0x2004)
        again = self.store(self.binop("Sub", self.sp(3), self.const(8)), 2, 0x2006)
        sdse, b = self.run_loop(8, body=(junk, again))
        assert junk not in b.statements and again not in b.statements, b.statements
        assert sdse.removed == 2


class TestLivenessWithUnplacedLoads(unittest.TestCase):
    """A frame load whose address cannot be placed reads every slot, but overwritten stores still die."""

    def setUp(self):
        self.arch = archinfo.ArchAMD64()
        self.m = ailment.Manager()

    def sbo(self, off):
        return StackBaseOffset(self.m.next_atom(), 64, off)

    def const(self, v):
        return Const(self.m.next_atom(), v, 64)

    def store(self, off, value, ins, guard=None):
        return Store(
            self.m.next_atom(), self.sbo(off), self.const(value), 8, self.arch.memory_endness, guard=guard, ins_addr=ins
        )

    def unplaced_read(self, ins):
        # sp - 64 + idx with an unbounded idx: on the frame, but anywhere on it
        idx = VirtualVariable(self.m.next_atom(), 7, 64, VirtualVariableCategory.REGISTER, oident=16)
        addr = BinaryOp(self.m.next_atom(), "Add", [self.sbo(-64), idx], False, bits=64)
        dst = VirtualVariable(self.m.next_atom(), 9, 64, VirtualVariableCategory.REGISTER, oident=24)
        return Assignment(
            self.m.next_atom(), dst, Load(self.m.next_atom(), addr, 8, self.arch.memory_endness), ins_addr=ins
        )

    def run_block(self, *stmts):
        block = Block(0x1000, 4 * len(stmts), statements=list(stmts))
        graph = networkx.DiGraph()
        graph.add_node(block)
        sdse = StackDeadStoreEliminator(self.arch, graph, ail_manager=self.m)
        sdse.run()
        return sdse, block

    def test_store_overwritten_before_the_read_is_removed(self):
        first, second, read = self.store(-8, 1, 0x1000), self.store(-8, 2, 0x1004), self.unplaced_read(0x1008)
        sdse, block = self.run_block(first, second, read)
        assert sdse.bailed_reason is not None
        assert first not in block.statements
        assert second in block.statements and read in block.statements

    def test_store_the_read_may_see_is_kept(self):
        first, read, second = self.store(-8, 1, 0x1000), self.unplaced_read(0x1004), self.store(-8, 2, 0x1008)
        _, block = self.run_block(first, read, second)
        assert first in block.statements

    def test_guarded_store_does_not_overwrite(self):
        guard = VirtualVariable(self.m.next_atom(), 5, 1, VirtualVariableCategory.REGISTER, oident=32)
        first, second = self.store(-8, 1, 0x1000), self.store(-8, 2, 0x1004, guard=guard)
        _, block = self.run_block(first, second, self.unplaced_read(0x1008))
        assert first in block.statements and second in block.statements


class TestReadsOfSlotsHandedToCalls(unittest.TestCase):
    """A read through a forwarded pointer to a slot a callee was given stays a pointer read."""

    def setUp(self):
        self.arch = archinfo.ArchAMD64()
        self.m = ailment.Manager()

    def sbo(self, off):
        return StackBaseOffset(self.m.next_atom(), 64, off)

    def load(self, addr, size=8):
        return Load(self.m.next_atom(), addr, size, self.arch.memory_endness)

    def run_block(self, pass_to_call: bool):
        call_arg = self.load(self.sbo(-16)) if pass_to_call else Const(self.m.next_atom(), 0, 64)
        dst = VirtualVariable(self.m.next_atom(), 9, 32, VirtualVariableCategory.REGISTER, oident=16)
        block = Block(
            0x1000,
            16,
            statements=[
                Store(self.m.next_atom(), self.sbo(-16), self.sbo(-24), 8, self.arch.memory_endness, ins_addr=0x1000),
                SideEffectStatement(
                    self.m.next_atom(),
                    Call(self.m.next_atom(), Const(self.m.next_atom(), 0x5000, 64), args=[call_arg]),
                    ins_addr=0x1004,
                ),
                Store(self.m.next_atom(), self.sbo(-16), self.sbo(-24), 8, self.arch.memory_endness, ins_addr=0x1008),
                Assignment(self.m.next_atom(), dst, self.load(self.load(self.sbo(-16)), 4), ins_addr=0x100C),
            ],
        )
        graph = networkx.DiGraph()
        graph.add_node(block)
        StackDeadStoreEliminator(self.arch, graph, ail_manager=self.m).run()
        return block.statements[-1].src.addr

    def test_slot_handed_to_a_callee_is_read_through_the_pointer(self):
        # stack SSA would not see the callee write sp-24 through a pointer it got from memory
        assert not isinstance(self.run_block(True), StackBaseOffset)

    def test_other_forwarded_reads_become_locals(self):
        addr = self.run_block(False)
        assert isinstance(addr, StackBaseOffset) and addr.offset == -24, addr


class TestEscapedFrameAddress(unittest.TestCase):
    """A pointer to one frame slot reaches its neighbours too: a VM indexes its stack from one such pointer."""

    def setUp(self):
        self.arch = archinfo.ArchAMD64()
        self.m = ailment.Manager()

    def sbo(self, off):
        return StackBaseOffset(self.m.next_atom(), 64, off)

    def const(self, v):
        return Const(self.m.next_atom(), v, 64)

    def store(self, addr, data, ins):
        return Store(self.m.next_atom(), addr, data, 8, self.arch.memory_endness, ins_addr=ins)

    def run_block(self, *stmts):
        block = Block(0x1000, 4 * len(stmts), statements=list(stmts))
        graph = networkx.DiGraph()
        graph.add_node(block)
        StackDeadStoreEliminator(self.arch, graph, ail_manager=self.m).run()
        return block

    def test_pointer_read_from_memory_reaches_beyond_the_escaped_slot(self):
        escape = self.store(self.const(0x600000), self.sbo(-0x40), 0x1000)
        neighbour = self.store(self.sbo(-0x38), self.const(5), 0x1004)
        # *(*(0x600000) + 8): through the escaped pointer, at the neighbouring slot
        ptr = Load(self.m.next_atom(), self.const(0x600000), 8, self.arch.memory_endness)
        addr = BinaryOp(self.m.next_atom(), "Add", [ptr, self.const(8)], False, bits=64)
        dst = VirtualVariable(self.m.next_atom(), 9, 64, VirtualVariableCategory.REGISTER, oident=16)
        read = Assignment(
            self.m.next_atom(), dst, Load(self.m.next_atom(), addr, 8, self.arch.memory_endness), ins_addr=0x1008
        )
        block = self.run_block(escape, neighbour, read)
        assert neighbour in block.statements

    def test_callee_reaches_beyond_the_escaped_slot(self):
        neighbour = self.store(self.sbo(-0x30), self.const(5), 0x1000)
        call = SideEffectStatement(
            self.m.next_atom(), Call(self.m.next_atom(), self.const(0x5000), args=[self.sbo(-0x40)]), ins_addr=0x1004
        )
        block = self.run_block(neighbour, call)
        assert neighbour in block.statements


class TestAlignedFrame(unittest.TestCase):
    """``(sp + off) & ~15`` is exact when sp's residue modulo 16 is known on entry, and opaque otherwise."""

    def setUp(self):
        self.arch = archinfo.ArchAMD64()
        self.m = ailment.Manager()

    def sbo(self, off):
        return StackBaseOffset(self.m.next_atom(), 64, off)

    def const(self, v):
        return Const(self.m.next_atom(), v, 64)

    def binop(self, op, a, b):
        return BinaryOp(self.m.next_atom(), op, [a, b], False, bits=64)

    def aligned(self, off, d=0):
        a = self.binop("And", self.sbo(off), self.const(0xFFFF_FFFF_FFFF_FFF0))
        return self.binop("Add", a, self.const(d)) if d else a

    def store(self, addr, value, ins):
        return Store(self.m.next_atom(), addr, self.const(value), 8, self.arch.memory_endness, ins_addr=ins)

    def read(self, addr, ins):
        dst = VirtualVariable(self.m.next_atom(), 9, 64, VirtualVariableCategory.REGISTER, oident=16)
        return Assignment(
            self.m.next_atom(), dst, Load(self.m.next_atom(), addr, 8, self.arch.memory_endness), ins_addr=ins
        )

    def run_block(self, *stmts, entry_sp_alignment=None):
        block = Block(0x1000, 4 * len(stmts), statements=list(stmts))
        graph = networkx.DiGraph()
        graph.add_node(block)
        sdse = StackDeadStoreEliminator(self.arch, graph, ail_manager=self.m, entry_sp_alignment=entry_sp_alignment)
        sdse.run()
        return sdse, block

    def test_abi_alignment_is_exact(self):
        # rsp + 8 is 16-aligned on entry, so (sp - 1028) & ~15 is sp - 1032
        store = self.store(self.aligned(-1028), 1, 0x1000)
        _, block = self.run_block(store, self.read(self.aligned(-1028), 0x1004))
        assert block.statements[0].addr.offset == -1032

    def test_known_entry_residue(self):
        junk = self.store(self.aligned(-1028, -8), 1, 0x1000)
        live = self.store(self.aligned(-1028, -8), 2, 0x1004)
        _, block = self.run_block(junk, live, self.read(self.sbo(-1048), 0x1008), entry_sp_alignment=(1 << 16, 0))
        # (sp - 1028) & ~15 == sp - 1040 for a 16-aligned entry sp
        assert junk not in block.statements
        assert block.statements[0].addr.offset == -1048

    def test_unknown_residue_stays_opaque(self):
        store = self.store(self.aligned(-1028), 1, 0x1000)
        sdse, block = self.run_block(store, self.read(self.sbo(-1040), 0x1004), entry_sp_alignment=(4, 0))
        (addr,) = sdse.resolve(self.aligned(-1028))
        assert addr.offset is None
        # it may be sp - 1040, so the read keeps it
        assert store in block.statements and not isinstance(block.statements[0].addr, StackBaseOffset)

    def test_vm_peepholes_align_exactly(self):
        import types

        from angr.analyses.decompiler.peephole_optimizations import (
            BasePointerOffsetAndMask,
            TidyStackAddr,
            TidyStackAddrExactAlignment,
            vm_peephole_optimizations,
        )

        opts = vm_peephole_optimizations()
        assert BasePointerOffsetAndMask not in opts and TidyStackAddr not in opts
        assert TidyStackAddrExactAlignment in opts
        project = types.SimpleNamespace(arch=self.arch)  # VM exploration from arch.initial_sp, 16-aligned
        opt = TidyStackAddrExactAlignment(project, None, self.m)
        folded = opt.optimize(self.aligned(-36))
        assert isinstance(folded, StackBaseOffset) and folded.offset == -48
        wide = self.binop("And", self.sbo(-36), self.const(0xFFFF_FFFF_FFFE_0000))
        assert opt.optimize(wide) is None


if __name__ == "__main__":
    unittest.main()
