#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Load,
    Phi,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, Return, SideEffectStatement, Store
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


def _cfg(blocks, edges):
    graph = networkx.DiGraph()
    graph.add_nodes_from(blocks.values())
    graph.add_edges_from((blocks[a], blocks[b]) for a, b in edges)
    return graph


def _phi(idx, dst, *entries):
    return Assignment(idx, dst, Phi(idx + 1, 64, [((addr, 0), vvar) for addr, vvar in entries]))


def _phi_sources(stmt):
    return {src[0]: vvar.varid for src, vvar in stmt.src.src_and_vvars}


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
        # the opaque access is based at another slot: s1's own address is not taken
        r0, s1, s2, idx = _reg(1), _slot(2, -0x10), _slot(3, -0x18), _reg(5)
        dynamic = BinaryOp(20, "Add", [idx, UnaryOp(21, "Reference", _slot(9, -0x40))], False, bits=64)
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

    def test_slot_written_through_its_address_is_not_substituted(self):
        # s1 = r0; f(&s1); return s1: f may have written s1
        r0, s1 = _reg(1), _slot(2, -0x10)
        call = SideEffectStatement(11, Call(20, Const(21, 0x402000, 64), args=[UnaryOp(22, "Reference", s1)]))
        graph, block = _graph(Assignment(10, s1, r0), call, Return(12, [s1]))
        StackCopyCoalescer(graph).run()
        assert _only(block, Return).ret_exprs[0].varid == s1.varid

    def test_copy_of_a_slot_written_through_its_address_is_not_substituted(self):
        # s1 = r0; s2 = s1; f(&s1); return s2: s2 holds s1's value from before the call
        r0, s1, s2 = _reg(1), _slot(2, -0x10), _slot(3, -0x18)
        call = SideEffectStatement(12, Call(20, Const(21, 0x402000, 64), args=[UnaryOp(22, "Reference", s1)]))
        graph, block = _graph(Assignment(10, s1, r0), Assignment(11, s2, s1), call, Return(13, [s2]))
        StackCopyCoalescer(graph).run()
        assert _only(block, Return).ret_exprs[0].varid == s2.varid

    def test_a_copy_is_forwarded_into_a_phi(self):
        # 1: s1 = r0; s2 = s1 -> 3    2: s3 = 5 -> 3    3: s4 = phi(1: s2, 2: s3)
        r0, s1, s2, s3, s4 = _reg(1), _slot(2, -0x10), _slot(3, -0x18), _slot(4, -0x18), _slot(5, -0x18)
        blocks = {
            0: Block(0, 1, statements=[Assignment(8, r0, Const(9, 1, 64))]),
            1: Block(1, 1, statements=[Assignment(10, s1, r0), Assignment(11, s2, s1)]),
            2: Block(2, 1, statements=[Assignment(12, s3, Const(13, 5, 64))]),
            3: Block(3, 1, statements=[_phi(14, s4, (1, s2), (2, s3)), Return(16, [s4])]),
        }
        graph = _cfg(blocks, [(0, 1), (0, 2), (1, 3), (2, 3)])
        coalescer = StackCopyCoalescer(graph, entry=blocks[0])
        coalescer.run()
        assert _phi_sources(blocks[3].statements[0]) == {1: r0.varid, 2: s3.varid}
        assert coalescer.removed == 2
        assert not blocks[1].statements

    def test_a_slot_permutation_becomes_crossed_phi_sources(self):
        # the loop body swaps two slots; the phis must read each other's value, and no copy may be lost
        a0, b0 = _slot(1, -0x10), _slot(2, -0x18)
        a1, b1 = _slot(3, -0x10), _slot(4, -0x18)
        a2, b2 = _slot(5, -0x10), _slot(6, -0x18)
        blocks = {
            0: Block(0, 1, statements=[Assignment(10, a0, Const(11, 1, 64)), Assignment(12, b0, Const(13, 2, 64))]),
            1: Block(1, 1, statements=[_phi(14, a1, (0, a0), (2, a2)), _phi(16, b1, (0, b0), (2, b2))]),
            2: Block(2, 1, statements=[Assignment(18, a2, b1), Assignment(19, b2, a1)]),
            3: Block(3, 1, statements=[Return(20, [a1, b1])]),
        }
        graph = _cfg(blocks, [(0, 1), (1, 2), (2, 1), (1, 3)])
        coalescer = StackCopyCoalescer(graph, entry=blocks[0])
        coalescer.run()
        assert _phi_sources(blocks[1].statements[0]) == {0: a0.varid, 2: b1.varid}
        assert _phi_sources(blocks[1].statements[1]) == {0: b0.varid, 2: a1.varid}
        assert coalescer.removed == 2

    def test_a_copy_that_does_not_dominate_the_phi_source_block_stays(self):
        # 1: s2 = s1 -> 3    2: -> 3    3: -> 4    4: s3 = phi(3: s2): s2 is not defined on the path through 2
        s1, s2, s3 = _slot(2, -0x10), _slot(3, -0x18), _slot(4, -0x18)
        blocks = {
            0: Block(0, 1, statements=[Assignment(10, s1, Const(11, 1, 64))]),
            1: Block(1, 1, statements=[Assignment(12, s2, s1)]),
            2: Block(2, 1, statements=[]),
            3: Block(3, 1, statements=[]),
            4: Block(4, 1, statements=[_phi(14, s3, (3, s2)), Return(16, [s3])]),
        }
        graph = _cfg(blocks, [(0, 1), (0, 2), (1, 3), (2, 3), (3, 4)])
        coalescer = StackCopyCoalescer(graph, entry=blocks[0])
        coalescer.run()
        assert _phi_sources(blocks[4].statements[0]) == {3: s2.varid}
        assert coalescer.removed == 0

    def test_a_phi_source_in_an_address_taken_slot_is_not_forwarded(self):
        # another version of s2's slot has its address taken: the slot is a memory location, keep the copy
        r0, s1, s2, s3, other = _reg(1), _slot(2, -0x10), _slot(3, -0x18), _slot(4, -0x18), _slot(7, -0x18)
        call = SideEffectStatement(17, Call(20, Const(21, 0x402000, 64), args=[UnaryOp(22, "Reference", other)]))
        blocks = {
            0: Block(0, 1, statements=[Assignment(10, s1, r0), Assignment(11, s2, s1)]),
            1: Block(1, 1, statements=[_phi(14, s3, (0, s2)), Assignment(16, other, s3), call]),
        }
        graph = _cfg(blocks, [(0, 1)])
        coalescer = StackCopyCoalescer(graph, entry=blocks[0])
        coalescer.run()
        assert _phi_sources(blocks[1].statements[0]) == {0: s2.varid}


if __name__ == "__main__":
    unittest.main()
