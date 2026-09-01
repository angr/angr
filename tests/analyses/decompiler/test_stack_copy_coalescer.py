#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Load,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, Store
from angr.analyses.decompiler.stack_copy_coalescer import StackCopyCoalescer

ENDNESS = "Iend_LE"


def _slot(varid, offset):
    return VirtualVariable(varid, varid, 64, VirtualVariableCategory.STACK, oident=offset)


def _reg(varid):
    return VirtualVariable(varid, varid, 64, VirtualVariableCategory.REGISTER, oident=16)


def _graph(*statements):
    block = Block(0x1000, 1, statements=list(statements))
    graph = networkx.DiGraph()
    graph.add_node(block)
    return graph, block


def _only(block, cls):
    found = [s for s in block.statements if isinstance(s, cls)]
    assert len(found) == 1, f"expected exactly one {cls.__name__}, got {len(found)}"
    return found[0]


class TestStackCopyCoalescer(unittest.TestCase):
    def test_a_chain_collapses_to_its_source(self):
        # s1 = r0; s2 = s1; store(s2)  =>  the store reads r0 and both copies go
        r0, s1, s2 = _reg(1), _slot(2, -0x10), _slot(3, -0x18)
        graph, block = _graph(
            Assignment(10, s1, r0),
            Assignment(11, s2, s1),
            Store(12, Const(13, 0x400000, 64), s2, 8, ENDNESS),
        )
        coalescer = StackCopyCoalescer(graph)
        coalescer.run()
        assert _only(block, Store).data.varid == r0.varid, "the store did not read the chain source"
        assert coalescer.removed == 2

    def test_a_reference_operand_is_never_substituted(self):
        # Reference(s2) is the address of s2's slot; rewriting it would address a different slot.
        r0, s1, s2 = _reg(1), _slot(2, -0x10), _slot(3, -0x18)
        graph, block = _graph(
            Assignment(10, s1, r0),
            Assignment(11, s2, s1),
            Store(12, UnaryOp(13, "Reference", s2), Const(14, 0, 64), 8, ENDNESS),
        )
        StackCopyCoalescer(graph).run()
        store = _only(block, Store)
        assert store.addr.op == "Reference"
        assert store.addr.operand.varid == s2.varid, "the address-of operand was rewritten"

    def test_an_unresolvable_frame_access_blocks_deletion(self):
        # A load indexed off a frame address by a non-constant can name a slot we would delete,
        # so nothing may be removed while one is present.
        r0, s1, s2, idx = _reg(1), _slot(2, -0x10), _slot(3, -0x18), _reg(5)
        dynamic = BinaryOp(20, "Add", [idx, UnaryOp(21, "Reference", s1)], False, bits=64)
        graph, block = _graph(
            Assignment(10, s1, r0),
            Assignment(11, s2, s1),
            Assignment(12, _slot(6, -0x28), Load(13, dynamic, 8, ENDNESS)),
        )
        coalescer = StackCopyCoalescer(graph)
        coalescer.run()
        assert coalescer.opaque_frame_access is True
        assert coalescer.removed == 0, "a copy was deleted despite an unresolvable frame access"
        assert len(block.statements) == 3

    def test_a_constant_offset_frame_access_does_not_block_deletion(self):
        # Reference(v) + const still names one slot, so it must not disable the pass.
        r0, s1, s2 = _reg(1), _slot(2, -0x10), _slot(3, -0x18)
        fixed = BinaryOp(20, "Add", [UnaryOp(21, "Reference", s1), Const(22, 8, 64)], False, bits=64)
        graph, block = _graph(
            Assignment(10, s1, r0),
            Assignment(11, s2, s1),
            Assignment(12, _slot(6, -0x28), Load(13, fixed, 8, ENDNESS)),
        )
        coalescer = StackCopyCoalescer(graph)
        coalescer.run()
        assert coalescer.opaque_frame_access is False
        assert coalescer.removed == 1, "the dead copy should have been removed"

    def test_propagation_happens_even_when_deletion_is_blocked(self):
        r0, s1, s2, idx = _reg(1), _slot(2, -0x10), _slot(3, -0x18), _reg(5)
        dynamic = BinaryOp(20, "Add", [idx, UnaryOp(21, "Reference", s1)], False, bits=64)
        graph, block = _graph(
            Assignment(10, s1, r0),
            Assignment(11, s2, s1),
            Store(12, Const(13, 0x400000, 64), s2, 8, ENDNESS),
            Assignment(14, _slot(6, -0x28), Load(15, dynamic, 8, ENDNESS)),
        )
        coalescer = StackCopyCoalescer(graph)
        coalescer.run()
        assert coalescer.removed == 0
        assert _only(block, Store).data.varid == r0.varid


if __name__ == "__main__":
    unittest.main()
