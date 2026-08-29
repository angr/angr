#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import sys
import unittest

import claripy

from angr.ailment.block import Block
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structurer_nodes import ConditionNode, SequenceNode

CPYTHON_DEFAULT_RECURSION_LIMIT = 1000
A_LIMIT_HIGHER_THAN_THE_WALKER_WANTS = 1_000_000


def nested_conditions(levels: int) -> tuple[Block | ConditionNode, list[int]]:
    """Build the shape a long chain of if statements structures into, plus the order its blocks are walked in.

    Every level is a ConditionNode with no else branch whose body holds one block and the next condition, which is
    what a function of several hundred sequentially guarded blocks produces.
    """
    node: Block | ConditionNode = Block(0, 1, statements=[])
    order = [0]
    for level in range(1, levels + 1):
        addr = level
        body = SequenceNode(addr, nodes=[Block(addr, 1, statements=[]), node])
        # SequenceWalker visits a sequence's nodes back to front, so the block of this level comes after its body.
        order.append(addr)
        node = ConditionNode(addr, None, claripy.BoolS(f"cond_{level}"), body)
    return node, order


class TestSequenceWalker(unittest.TestCase):
    def test_deeply_nested_tree_walks_at_the_default_recursion_limit(self):
        # The default limit walks 248 levels and fails at 249; the deepest tree measured on a real function was
        # 519. 800 is past both and inside the roughly 2500 that CPython's separate C budget still allows.
        root, expected = nested_conditions(800)
        visited = []

        walker = SequenceWalker(handlers={Block: lambda block, **kwargs: visited.append(block.addr)})

        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(CPYTHON_DEFAULT_RECURSION_LIMIT)
        try:
            walker.walk(root)
        finally:
            sys.setrecursionlimit(old_limit)

        assert visited == expected

    def test_walk_leaves_a_higher_recursion_limit_alone(self):
        root, _ = nested_conditions(1)
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(A_LIMIT_HIGHER_THAN_THE_WALKER_WANTS)
        try:
            SequenceWalker().walk(root)
            assert sys.getrecursionlimit() == A_LIMIT_HIGHER_THAN_THE_WALKER_WANTS
        finally:
            sys.setrecursionlimit(old_limit)


if __name__ == "__main__":
    unittest.main()
