#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import collections
import unittest

import archinfo

from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Register, Tmp
from angr.ailment.statement import Assignment, ConditionalJump, Jump
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.structurer_nodes import SequenceNode
from angr.analyses.decompiler.structuring.structurer_base import StructurerBase


def _blocks(node):
    """Every AIL block reachable in a structured node, in tree order."""
    out = []
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, Block):
            out.append(n)
        elif isinstance(n, SequenceNode):
            stack.extend(reversed(n.nodes))
    return out


class TestBreakRewriteInstructionBoundary(unittest.TestCase):
    """
    _rewrite_conditional_jumps_to_breaks cuts an AIL block at a loop-exit jump and builds one block per piece
    from the ins_addr of that piece's first statement. A rep-prefixed string instruction lifts to a block whose
    counter guard is an internal branch *between statements of the one instruction*, so both pieces take the
    same ins_addr and keep the original idx: two blocks end up sharing one (addr, idx) identity, and the VEX
    temporary defined before the cut is used after it. Temporaries are block-local, so the second piece reads
    one that is no longer defined, and block simplification later raises KeyError on it.
    """

    @staticmethod
    def _structurer():
        """The rewrite touches only cond_proc on the instance, so the real break-node path runs."""
        st = object.__new__(StructurerBase)
        st.cond_proc = ConditionProcessor(archinfo.ArchX86(), Manager(arch=archinfo.ArchX86()))
        return st

    @staticmethod
    def _one_instruction_loop_body(m, ins_addr=0x1000, exit_addr=0x2000):
        """The rep-movs shape: counter read, loop-exit branch, counter decrement -- all one instruction."""
        t1 = Tmp(m.next_atom(), 1, 32)
        stmts = [
            Assignment(m.next_atom(), t1, Register(m.next_atom(), 12, 32), ins_addr=ins_addr),
            ConditionalJump(
                m.next_atom(),
                t1,
                Const(m.next_atom(), exit_addr, 32),
                Const(m.next_atom(), ins_addr, 32),
                ins_addr=ins_addr,
            ),
            Assignment(
                m.next_atom(),
                Register(m.next_atom(), 12, 32),
                BinaryOp(m.next_atom(), "Sub", [t1, Const(m.next_atom(), 1, 32)], False),
                ins_addr=ins_addr,
            ),
            # the tail needs two statements: with exactly one after the jump a *different* defect
            # (the tail gate at the rebuild) drops it outright, and this one never gets to fire
            Assignment(
                m.next_atom(),
                Register(m.next_atom(), 32, 32),
                BinaryOp(m.next_atom(), "Add", [t1, Const(m.next_atom(), 2, 32)], False),
                ins_addr=ins_addr,
            ),
        ]
        return SequenceNode(ins_addr, nodes=[Block(ins_addr, 4, statements=stmts, idx=None)])

    def test_a_cut_inside_one_instruction_is_not_taken(self):
        m = Manager(arch=None)
        body = self._one_instruction_loop_body(m)
        StructurerBase._rewrite_conditional_jumps_to_breaks(self._structurer(), body, {0x2000})

        blocks = [b for b in _blocks(body) if b.statements]
        identities = collections.Counter((b.addr, b.idx) for b in blocks)
        # the identity of an AIL block is (addr, idx); two pieces of one instruction would collide
        assert all(n == 1 for n in identities.values()), f"duplicate block identities: {identities}"

        # and the temporary keeps its definition in the same block as its use
        for b in blocks:
            defined = {s.dst.tmp_idx for s in b.statements if isinstance(s, Assignment) and isinstance(s.dst, Tmp)}
            used = {
                a.tmp_idx
                for s in b.statements
                if isinstance(s, Assignment) and isinstance(s.src, BinaryOp)
                for a in s.src.operands
                if isinstance(a, Tmp)
            }
            assert used <= defined, f"block {b.addr:#x} uses undefined temporaries {used - defined}"

    def test_a_cut_on_an_instruction_boundary_is_still_taken(self):
        m = Manager(arch=None)
        # the loop-exit jump is the last statement of its own instruction, so cutting there is safe
        stmts = [
            Assignment(m.next_atom(), Register(m.next_atom(), 8, 32), Const(m.next_atom(), 0, 32), ins_addr=0x1000),
            ConditionalJump(
                m.next_atom(),
                Const(m.next_atom(), 1, 32),
                Const(m.next_atom(), 0x2000, 32),
                Const(m.next_atom(), 0x1008, 32),
                ins_addr=0x1004,
            ),
            Jump(m.next_atom(), Const(m.next_atom(), 0x1000, 32), ins_addr=0x1008),
        ]
        body = SequenceNode(0x1000, nodes=[Block(0x1000, 12, statements=stmts, idx=None)])
        StructurerBase._rewrite_conditional_jumps_to_breaks(self._structurer(), body, {0x2000})

        # the rewrite fired: the original block was emptied and replaced by pieces
        assert len(_blocks(body)) > 1


if __name__ == "__main__":
    unittest.main()
