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
    Const,
    Load,
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, Store
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
        m = ailment.Manager(arch=arch)

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


if __name__ == "__main__":
    unittest.main()
