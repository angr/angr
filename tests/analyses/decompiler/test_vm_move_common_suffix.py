#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from types import SimpleNamespace

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import Const, Load, Register
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label, Store
from angr.analyses.decompiler.vm_deobfuscation_simplifier import VMDeobfuscationSimplifierMixin


def _store(idx, addr, value):
    return Store(idx, Const(idx + 1, addr, 64), Const(idx + 2, value, 32), 4, "Iend_LE")


def _cond_block(addr, block_idx, true_target, false_target):
    cond = Load(addr + 3, Const(addr + 4, 0x7C0007, 64), 1, "Iend_LE")
    return Block(
        addr,
        1,
        statements=[
            Label(addr, f"L{addr:x}"),
            ConditionalJump(addr + 1, cond, Const(addr + 5, true_target, 64), Const(addr + 6, false_target, 64)),
        ],
        idx=block_idx,
    )


def _run(graph):
    out = VMDeobfuscationSimplifierMixin.move_common_suffix_to_next_node(SimpleNamespace(), graph)
    return {(b.addr, b.idx or 0): b for b in out}


class TestMoveCommonSuffixToNextNode(unittest.TestCase):
    def test_duplicated_conditional_jump_stays_in_place(self):
        # a conditional-jump block duplicated per predecessor: both copies are identical preds of each target, but
        # their conditional jump must not be hoisted into either target
        p0 = Block(0x1000, 1, statements=[_store(0x1001, 0x100, 1), Jump(0x1004, Const(0x1005, 0x3000, 64))])
        p1 = Block(0x2000, 1, statements=[_store(0x2001, 0x100, 2), Jump(0x2004, Const(0x2005, 0x3000, 64))])
        c0 = _cond_block(0x3000, 0, 0x4000, 0x5000)
        c1 = _cond_block(0x3000, 1, 0x4000, 0x5000)
        t = Block(0x4000, 1, statements=[Label(0x4000, "L4000"), _store(0x4001, 0x200, 3)])
        f = Block(0x5000, 1, statements=[Label(0x5000, "L5000"), _store(0x5001, 0x300, 4)])
        graph = networkx.DiGraph()
        graph.add_edges_from([(p0, c0), (p1, c1), (c0, t), (c0, f), (c1, t), (c1, f)])

        blocks = _run(graph)
        for key in ((0x3000, 0), (0x3000, 1)):
            assert isinstance(blocks[key].statements[-1], ConditionalJump)
        assert len(blocks[(0x4000, 0)].statements) == 2
        assert len(blocks[(0x5000, 0)].statements) == 2

    def test_common_suffix_of_branch_arms_is_hoisted(self):
        a = Block(
            0x1000,
            1,
            statements=[
                Label(0x1000, "L1000"),
                Assignment(0x1001, Register(0x1002, 16, 64), Const(0x1003, 1, 64)),
                _store(0x1004, 0x100, 7),
                Jump(0x1008, Const(0x1009, 0x3000, 64)),
            ],
        )
        b = Block(
            0x2000,
            1,
            statements=[
                Label(0x2000, "L2000"),
                Assignment(0x2001, Register(0x2002, 16, 64), Const(0x2003, 2, 64)),
                _store(0x2004, 0x100, 7),
                Jump(0x2008, Const(0x2009, 0x3000, 64)),
            ],
        )
        join = Block(0x3000, 1, statements=[Label(0x3000, "L3000"), _store(0x3001, 0x200, 1)])
        graph = networkx.DiGraph()
        graph.add_edges_from([(a, join), (b, join)])

        blocks = _run(graph)
        for key in ((0x1000, 0), (0x2000, 0)):
            stmts = blocks[key].statements
            assert len(stmts) == 3 and isinstance(stmts[1], Assignment) and isinstance(stmts[2], Jump), stmts
        stmts = blocks[(0x3000, 0)].statements
        assert len(stmts) == 3 and stmts[0].name == "L3000"
        assert stmts[1].likes(_store(0, 0x100, 7))


if __name__ == "__main__":
    unittest.main()
