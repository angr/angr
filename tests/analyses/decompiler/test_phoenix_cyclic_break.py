#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""
Regression tests for the break that cyclic refinement builds out of a loop exit edge whose source node
has no other successor in the graph.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from typing import Any

import archinfo
import networkx

import angr
from angr import ailment
from angr.ailment.expression import Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import ConditionalJump, Jump, Return, Store
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.structurer_nodes import BreakNode, ConditionNode, SequenceNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer
from tests.common import bin_location

HEAD = 0x1000
LATCH = 0x1010
EXITING = 0x1020
# where the second of the exiting block's two string instructions starts
SECOND = 0x1022
# where the exiting block ends. A lifter that unrolls a string instruction into a loop exits that loop
# to the next instruction; for the block's last instruction that is the end of the block, which is
# where the block's terminal jump goes as well, so the end of the block is the loop successor (see
# the `rep stosq` example in `is_head_controlled_loop_block`).
SUCCESSOR = 0x1024
# a block the compound source node runs after the exiting block. Structuring builds a sequence out of
# blocks wherever they lie, so this need not start where the exiting block ends -- and here it cannot,
# because that address is the successor.
TAIL = 0x1028
# named by the conditional variant's terminal jump and deliberately absent from the graph, which is
# what sends refinement down the branch that needs an "other target"
ELSEWHERE = 0x1040


def _build(arch, terminal: str, *, internal_target: int = EXITING, compound: bool = False):
    """A cyclic region whose exit edge leaves from a block with an internal back edge.

    HEAD branches to the exiting node or to LATCH, and LATCH loops back to HEAD or leaves for the loop
    successor. With two exits the loop matches no loop schema outright, so the structurer refines it,
    turning each exit edge into a break. The exiting block holds two string instructions a lifter has unrolled
    into copy loops, each leaving one conditional jump in the block. The first names only its own back
    edge -- `internal_target`, by default the block's own address -- and otherwise falls through into
    the second, so it never leaves the block. The second names its back edge and its exit, the end of
    the block. After them comes one of two terminals: a plain jump to the loop successor, or a
    conditional jump naming a second target that is not in the graph. With the plain jump, the exit is
    what makes the block a head-controlled loop at all: only a conditional jump that can leave the
    block counts (`is_head_controlled_loop_jump`), and the edge condition is then read off the first
    internal conditional jump, which describes a back edge and not the exit edge.

    With `compound`, the graph node is a SequenceNode holding the exiting block followed by a store
    and a return, so the block carrying the exit edge is not the last thing the node runs.

    Returns the region and its AIL manager.
    """
    manager = ailment.Manager()

    def condition(ident):
        return VirtualVariable(
            manager.next_atom(), ident, 1, VirtualVariableCategory.REGISTER, oident=arch.registers["rax"][0]
        )

    head = ailment.Block(
        HEAD,
        4,
        statements=[
            ConditionalJump(
                manager.next_atom(),
                condition(1),
                Const(manager.next_atom(), EXITING, arch.bits),
                Const(manager.next_atom(), LATCH, arch.bits),
                ins_addr=HEAD,
            )
        ],
    )
    latch = ailment.Block(
        LATCH,
        4,
        statements=[
            ConditionalJump(
                manager.next_atom(),
                condition(5),
                Const(manager.next_atom(), HEAD, arch.bits),
                Const(manager.next_atom(), SUCCESSOR, arch.bits),
                ins_addr=LATCH,
            )
        ],
    )
    if terminal == "jump":
        terminal_stmt = Jump(manager.next_atom(), Const(manager.next_atom(), SUCCESSOR, arch.bits), ins_addr=EXITING)
    else:
        assert terminal == "condjump"
        terminal_stmt = ConditionalJump(
            manager.next_atom(),
            condition(3),
            Const(manager.next_atom(), SUCCESSOR, arch.bits),
            Const(manager.next_atom(), ELSEWHERE, arch.bits),
            ins_addr=EXITING,
        )
    exiting = ailment.Block(
        EXITING,
        4,
        statements=[
            ConditionalJump(
                manager.next_atom(),
                condition(2),
                Const(manager.next_atom(), internal_target, arch.bits),
                None,
                ins_addr=EXITING,
            ),
            # the second instruction's copy loop: back to itself, or out to the end of the block
            ConditionalJump(
                manager.next_atom(),
                condition(4),
                Const(manager.next_atom(), SECOND, arch.bits),
                Const(manager.next_atom(), SUCCESSOR, arch.bits),
                ins_addr=SECOND,
            ),
            terminal_stmt,
        ],
    )
    if compound:
        tail = ailment.Block(
            TAIL,
            4,
            statements=[
                Store(
                    manager.next_atom(),
                    Const(manager.next_atom(), 0x4000, arch.bits),
                    Const(manager.next_atom(), 1, arch.bits),
                    arch.bytes,
                    archinfo.Endness.LE,
                    ins_addr=TAIL,
                ),
                Return(manager.next_atom(), [], ins_addr=TAIL),
            ],
        )
        source: Any = SequenceNode(EXITING, nodes=[exiting, tail])
    else:
        source = exiting
    successor = ailment.Block(SUCCESSOR, 4, statements=[Return(manager.next_atom(), [], ins_addr=SUCCESSOR)])

    shared = networkx.DiGraph([(head, latch), (head, source), (latch, head), (latch, successor), (source, successor)])
    region = OverlayManager(shared).root.create_subregion(head, {head, latch, source}, cyclic=True)
    return region, manager


def _structure(terminal: str, **kwargs):
    """Structure the region `_build` makes, letting any exception through."""
    project = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
    region, manager = _build(project.arch, terminal, **kwargs)
    return project.analyses[PhoenixStructurer].prep(fail_fast=True)(region, ail_manager=manager).result


def _nodes(node):
    yield node
    for child in getattr(node, "nodes", None) or ():
        yield from _nodes(child)
    for attr in ("node", "sequence_node", "true_node", "false_node"):
        child = getattr(node, attr, None)
        if child is not None:
            yield from _nodes(child)


def _jump_targets(node):
    return [
        stmt.target.value
        for block in _nodes(node)
        if isinstance(block, ailment.Block)
        for stmt in block.statements
        if isinstance(stmt, Jump)
    ]


class TestCyclicRefinementBreak(unittest.TestCase):
    def test_plain_terminal_jump_becomes_an_unconditional_break(self):
        """
        Every way out of the exiting block reaches the loop successor, and the block is the last
        thing its node runs, so the break is unconditional however the edge condition came out.
        This used to raise TypeError.
        """
        result = _structure("jump")

        assert [node.target for node in _nodes(result) if type(node) is BreakNode] == [SUCCESSOR]
        # and the terminal jump is gone rather than left behind as a goto
        assert _jump_targets(result) == []

    def test_conditional_terminal_jump_still_breaks_conditionally(self):
        """
        When the exiting block ends in a conditional jump that names a second target, the break stays
        conditional, with its fallthrough to the absent target.
        """
        result = _structure("condjump")

        conditions = [node for node in _nodes(result) if isinstance(node, ConditionNode) and node.false_node]
        assert len(conditions) == 1
        assert [node.target for node in _nodes(conditions[0].true_node) if type(node) is BreakNode] == [SUCCESSOR]
        assert _jump_targets(conditions[0].false_node) == [ELSEWHERE]

    def test_an_internal_jump_that_leaves_the_block_is_not_unconditional(self):
        """
        A conditional jump inside the block that targets neither the block itself nor the loop
        successor leaves the block for somewhere else, and an unconditional break would drop that
        path, so refinement refuses to emit one.
        """
        with self.assertRaises(TypeError):
            _structure("jump", internal_target=ELSEWHERE)

    def test_a_block_with_code_after_it_is_not_broken_out_of_unconditionally(self):
        """
        The exit edge leaves a graph node, but the break is written at a block found inside it, and
        those differ whenever the node has already been structured. An unconditional break at that
        block's position jumps over everything the node runs afterwards, so refinement refuses when
        the block is not the last thing the node runs -- here a store and a return follow it.
        """
        with self.assertRaises(TypeError):
            _structure("jump", compound=True)


if __name__ == "__main__":
    unittest.main()
