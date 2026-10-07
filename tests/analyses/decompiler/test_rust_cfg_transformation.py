#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Register
from angr.ailment.statement import ConditionalJump, Jump
from angr.rust.mixins.cfg_transformation_mixin import CFGTransformationMixin


def _terminator_targets(block):
    stmt = block.statements[-1]
    if isinstance(stmt, Jump):
        return {stmt.target.value_int}
    return {t.value_int for t in (stmt.true_target, stmt.false_target) if isinstance(t, Const)}


def _dangling_terminators(graph):
    """Terminators jumping to an address that is not a block of the graph."""
    addrs = {b.addr for b in graph.nodes}
    out = []
    for b in graph.nodes:
        if not b.statements or not isinstance(b.statements[-1], (Jump, ConditionalJump)):
            continue
        out += [(b.addr, b.idx, t) for t in _terminator_targets(b) - addrs]
    return out


class TestRustCFGTransformation(unittest.TestCase):
    """
    replace_jump_target() has to rewrite the terminator as well as the graph edge. AIL expressions are immutable, so
    the branch that mutated stmt.true_target.value in place changed nothing, and the block was left jumping to a block
    that the caller went on to delete.
    """

    @staticmethod
    def _graph_with_condjump():
        m = Manager()
        cond = BinaryOp(m.next_atom(), "CmpEQ", [Register(m.next_atom(), 16, 64), Const(m.next_atom(), 0, 64)], False)
        head = Block(
            0x100,
            1,
            statements=[
                ConditionalJump(
                    m.next_atom(),
                    cond,
                    Const(m.next_atom(), 0x200, 64),
                    Const(m.next_atom(), 0x300, 64),
                    ins_addr=0x100,
                )
            ],
        )
        doomed = Block(0x200, 1, statements=[Jump(m.next_atom(), Const(m.next_atom(), 0x400, 64), ins_addr=0x200)])
        other = Block(0x300, 1, statements=[])
        successor = Block(0x400, 1, statements=[])
        graph = networkx.DiGraph()
        graph.add_edge(head, doomed)
        graph.add_edge(head, other)
        graph.add_edge(doomed, successor)
        return head, doomed, other, successor, graph

    def test_true_branch_target_is_rewritten(self):
        head, doomed, _, successor, graph = self._graph_with_condjump()
        transformer = CFGTransformationMixin(graph)

        transformer.replace_jump_target(head, 0x200, None, 0x400, None)

        assert _terminator_targets(head) == {0x400, 0x300}
        assert graph.has_edge(head, successor)
        assert not graph.has_edge(head, doomed)

    def test_false_branch_target_is_rewritten(self):
        head, _, other, successor, graph = self._graph_with_condjump()
        transformer = CFGTransformationMixin(graph)

        transformer.replace_jump_target(head, 0x300, None, 0x400, None)

        assert _terminator_targets(head) == {0x200, 0x400}
        assert graph.has_edge(head, successor)
        assert not graph.has_edge(head, other)

    def test_condjump_collapses_when_both_branches_converge(self):
        # the other pre-existing path: replacing one target with the other one turns the branch into a plain jump
        head, _, _, _, graph = self._graph_with_condjump()
        transformer = CFGTransformationMixin(graph)

        transformer.replace_jump_target(head, 0x200, None, 0x300, None)

        assert isinstance(head.statements[-1], Jump)
        assert _terminator_targets(head) == {0x300}

    def test_removing_a_block_leaves_no_dangling_terminator(self):
        _, doomed, _, _, graph = self._graph_with_condjump()
        transformer = CFGTransformationMixin(graph)

        assert transformer.remove_block(doomed)

        assert doomed not in graph
        assert not _dangling_terminators(graph)


if __name__ == "__main__":
    unittest.main()
