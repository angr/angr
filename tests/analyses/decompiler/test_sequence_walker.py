#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,unused-argument
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import claripy
from angr.ailment.block import Block
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structurer_nodes import ConditionNode, SequenceNode
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# A recursive walk of this tree needs four interpreter frames per level, so it stops at 248 levels under CPython's
# default limit. The deepest tree measured on a real function was 519. This is far enough past both that no
# recursion limit a caller could reasonably have raised would let the recursive walk through.
LEVELS = 5000


def nested_conditions(levels: int) -> tuple[Block | ConditionNode, list[int]]:
    """
    Build the shape a long chain of guarded statements structures into, and the order its blocks are walked in.

    Every level is a ConditionNode with no else branch whose body holds one block and the next condition.
    """
    node: Block | ConditionNode = Block(0, 1, statements=[])
    order = [0]
    for level in range(1, levels + 1):
        body = SequenceNode(level, nodes=[Block(level, 1, statements=[]), node])
        # A sequence's nodes are walked back to front, so the block of this level comes after its body.
        order.append(level)
        node = ConditionNode(level, None, claripy.BoolS(f"cond_{level}"), body)
    return node, order


class TestSequenceWalker(unittest.TestCase):
    def test_a_deeply_nested_function_decompiles(self):
        # main is two hundred guarded statements, which structures into a tree about four hundred nodes deep. A
        # recursive walk of it runs out of interpreter frames and the decompiler records the RecursionError instead
        # of producing any output.
        proj = angr.Project(os.path.join(test_location, "x86_64", "deeply_nested_ifs"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        decompiler = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg.model)

        codegen = decompiler.codegen
        assert not decompiler.errors
        assert codegen is not None
        text = codegen.text
        assert text is not None
        assert text.count("if (") >= 200

    def test_deeply_nested_tree_is_walked_in_order(self):
        root, expected = nested_conditions(LEVELS)
        visited = []

        SequenceWalker(handlers={Block: lambda block, **kwargs: visited.append(block.addr)}).walk(root)

        assert visited == expected

    def test_deeply_nested_tree_is_rebuilt_from_the_replacements(self):
        root, _ = nested_conditions(LEVELS)

        walker = SequenceWalker(
            handlers={Block: lambda block, **kwargs: Block(block.addr + 1, block.original_size, statements=[])},
            update_seqnode_in_place=False,
        )
        new_root = walker.walk(root)

        node = new_root
        for level in range(LEVELS, 0, -1):
            assert isinstance(node, ConditionNode)
            assert node.addr == level
            block, node = node.true_node.nodes
            assert block.addr == level + 1
        assert isinstance(node, Block)
        assert node.addr == 1

    def test_a_generator_handler_is_walked_on_the_stack(self):
        root, _ = nested_conditions(LEVELS)
        visited = []

        def walk_condition(node, **kwargs):
            visited.append(node.addr)
            return (yield node.true_node, {"parent": node, "index": 0})

        SequenceWalker(
            handlers={
                ConditionNode: walk_condition,
                Block: lambda block, **kwargs: visited.append(block.addr),
            }
        ).walk(root)

        # Every condition on the way down, then every block on the way back up.
        assert visited == list(range(LEVELS, -1, -1)) + list(range(1, LEVELS + 1))

    def test_a_replaced_handler_runs_for_every_node_of_its_type(self):
        seen_by_subclass = []
        seen_by_argument = []

        class CountingWalker(SequenceWalker):
            def _handle_Condition(self, node, **kwargs):
                seen_by_subclass.append(node.addr)
                return super()._handle_Condition(node, **kwargs)

        CountingWalker().walk(nested_conditions(3)[0])
        SequenceWalker(handlers={ConditionNode: lambda node, **kwargs: seen_by_argument.append(node.addr)}).walk(
            nested_conditions(3)[0]
        )

        assert seen_by_subclass == [3, 2, 1]
        # A handler passed in replaces the walk into the node as well as the work done at it, so nothing below the
        # outermost condition is reached.
        assert seen_by_argument == [3]

    def test_a_replaced_handle_sees_every_node(self):
        seen = []

        class RecordingWalker(SequenceWalker):
            def _handle(self, node, **kwargs):
                seen.append(node.__class__.__name__)
                return super()._handle(node, **kwargs)

        RecordingWalker().walk(nested_conditions(3)[0])

        assert seen == [
            "ConditionNode",
            "SequenceNode",
            "ConditionNode",
            "SequenceNode",
            "ConditionNode",
            "SequenceNode",
            "Block",
            "Block",
            "Bool",
            "Block",
            "Bool",
            "Block",
            "Bool",
        ]


if __name__ == "__main__":
    unittest.main()
