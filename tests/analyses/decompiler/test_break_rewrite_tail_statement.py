#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import Const, Register
from angr.ailment.statement import Assignment, ConditionalJump
from angr.analyses.decompiler.structurer_nodes import SequenceNode
from angr.analyses.decompiler.structuring.structurer_base import StructurerBase


def _statements(node):
    """Every AIL statement reachable in a structured node, in tree order."""
    out = []
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, Block):
            out.extend(n.statements)
        elif isinstance(n, SequenceNode):
            stack.extend(reversed(n.nodes))
    return out


class TestBreakRewriteTailStatement(unittest.TestCase):
    """
    _rewrite_conditional_jumps_to_breaks replaces an AIL block that exits a loop with one block per
    piece: the statements before the loop-exit jump, the break itself, and the statements after it.
    The original block is emptied once the pieces are in place, so any piece the rebuild does not
    emit is gone from the output -- with no exception and no log record.
    """

    @staticmethod
    def _structurer():
        # the rewrite needs only this one collaborator, so the analysis is never constructed
        st = object.__new__(StructurerBase)
        setattr(  # noqa: B010
            st,
            "_loop_create_break_node",
            lambda stmt, addrs: Block(stmt.tags["ins_addr"], 0, statements=[], idx=None),
        )
        return st

    @staticmethod
    def _loop_body(m, tail_len: int, ins_addr: int = 0x1000, exit_addr: int = 0x2000):
        """A loop-exit branch with ``tail_len`` ordinary statements after it."""
        stmts = [
            Assignment(m.next_atom(), Register(m.next_atom(), 8, 32), Const(m.next_atom(), 0, 32), ins_addr=ins_addr),
            ConditionalJump(
                m.next_atom(),
                Const(m.next_atom(), 1, 32),
                Const(m.next_atom(), exit_addr, 32),
                Const(m.next_atom(), ins_addr + 8, 32),
                ins_addr=ins_addr + 4,
            ),
        ]
        for i in range(tail_len):
            stmts.append(
                Assignment(
                    m.next_atom(),
                    Register(m.next_atom(), 20 + i, 32),
                    Const(m.next_atom(), 42 + i, 32),
                    ins_addr=ins_addr + 8 + 4 * i,
                )
            )
        return stmts, SequenceNode(ins_addr, nodes=[Block(ins_addr, 8 + 4 * tail_len, statements=stmts, idx=None)])

    def _rewrite(self, tail_len: int):
        m = Manager()
        stmts, body = self._loop_body(m, tail_len)
        StructurerBase._rewrite_conditional_jumps_to_breaks(self._structurer(), body, {0x2000})
        return stmts, _statements(body)

    def test_a_single_statement_after_the_exit_jump_survives(self):
        stmts, surviving = self._rewrite(1)
        # the jump itself becomes the break, so every other statement must still be there
        assert any(s is stmts[2] for s in surviving), f"the statement after the loop-exit jump was dropped: {surviving}"
        assert any(s is stmts[0] for s in surviving)

    def test_two_statements_after_the_exit_jump_survive(self):
        # the tail block was always emitted for a tail of two or more; pin that it still is
        stmts, surviving = self._rewrite(2)
        assert any(s is stmts[2] for s in surviving)
        assert any(s is stmts[3] for s in surviving)
        assert any(s is stmts[0] for s in surviving)


if __name__ == "__main__":
    unittest.main()
