#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""
Regression tests for the break that cyclic refinement builds out of a loop exit edge.

`_refine_cyclic_core` wants a second target when the recovered edge condition is not trivially
true: either a second successor of the source node in the graph, or a second target named by the
statement that leaves the source block. With neither, and a statement that is not a branch, it used
to raise `TypeError`.

Such a statement has no second target to offer at all, and then the only sound reading is that the
edge is unconditional -- which the block's own statements have to establish, because the code that
recovers an edge condition out of a block holding more than one conditional jump can pick the wrong
one.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import types
import unittest
from typing import Any, cast

import archinfo
import networkx

from angr import ailment
from angr.ailment.expression import Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import ConditionalJump, Jump, Return, Store
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.structurer_nodes import ConditionNode, SequenceNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer
from angr.utils.graph import DirectedGraphHelper

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


def _build(terminal: str, *, internal_target: int = EXITING, compound: bool = False):
    """A cyclic region whose exit edge leaves from a block with an internal back edge.

    HEAD branches to the exiting node or to LATCH, LATCH jumps back to HEAD, and the exiting node is
    the only way out of the loop. The exiting block holds two string instructions a lifter has unrolled
    into copy loops, each leaving one conditional jump in the block. The first names only its own back
    edge -- `internal_target`, by default the block's own address -- and otherwise falls through into
    the second, so it never leaves the block. The second names its back edge and its exit, the end of
    the block. After them comes one of two terminals: a plain jump to the loop successor, or a
    conditional jump naming a second target that is not in the graph. With the plain jump, the exit is
    what makes the block a head-controlled loop at all: only a conditional jump that can leave the
    block counts (`is_head_controlled_loop_jump`), and the edge condition is then read off the *first*
    internal conditional jump, which describes a back edge and not the exit edge.

    With `compound`, the graph node is a SequenceNode holding the exiting block followed by a store
    and a return, so the block carrying the exit edge is not the last thing the node runs.

    Returns the structurer, its region, and the loop head. Only the nine attributes the path reads
    are set, in the manner of `test_dowhile_latch_continue`: the analysis's own `__init__` runs the
    whole algorithm, which is not what is under test here.
    """
    arch = archinfo.ArchAMD64()
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
        statements=[Jump(manager.next_atom(), Const(manager.next_atom(), HEAD, arch.bits), ins_addr=LATCH)],
    )
    if terminal == "jump":
        terminal_stmt = Jump(manager.next_atom(), Const(manager.next_atom(), SUCCESSOR, arch.bits), ins_addr=EXITING)
    else:
        assert terminal == "condjump"
        # names a second target as well as the successor
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

    shared = networkx.DiGraph([(head, latch), (head, source), (latch, head), (source, successor)])
    region = OverlayManager(shared).root.create_subregion(head, {head, latch, source}, cyclic=True)

    structurer = object.__new__(PhoenixStructurer)
    structurer._region = region
    structurer._parent_region = None
    structurer.cond_proc = ConditionProcessor(arch, manager)
    structurer.ail_manager = manager
    # the refinement reads nothing from the project but the pointer width, and nothing from the
    # graph helper that the region's own graph does not answer; cast so the stand-ins can be
    # assigned to attributes annotated for the real Project and the real element type
    structurer.project = cast(Any, types.SimpleNamespace(arch=arch))
    structurer._graph_helper = cast(Any, DirectedGraphHelper(region.graph_with_successors, True, head))
    structurer.virtualized_edges = set()
    structurer.dowhile_known_tail_nodes = set()
    structurer.jump_tables = {}
    return structurer, region, head


def _refined_exiting_node(region):
    """The node cyclic refinement left in place of the exiting block."""
    nodes = [node for node in region.raw_graph.filtered() if node.addr == EXITING]
    assert len(nodes) == 1
    return nodes[0]


def _jump_targets(block):
    return [stmt.target.value for stmt in block.statements if isinstance(stmt, Jump)]


class TestCyclicRefinementBreak(unittest.TestCase):
    def test_plain_terminal_jump_becomes_an_unconditional_break(self):
        """
        The exiting block's only way out is its terminal jump to the loop successor, and it is the
        last thing its node runs, so the break is unconditional however the edge condition came
        out. This used to raise TypeError.
        """
        structurer, region, head = _build("jump")

        assert structurer._refine_cyclic_core(head, {head}) is True

        refined = _refined_exiting_node(region)
        assert isinstance(refined, SequenceNode)
        body, break_node = refined.nodes
        # the block keeps both copy loops and loses only its terminal jump
        assert [isinstance(stmt, ConditionalJump) for stmt in body.statements] == [True, True]
        # and the break is a plain jump to the loop successor, not a condition node
        assert not isinstance(break_node, ConditionNode)
        assert _jump_targets(break_node) == [SUCCESSOR]

    def test_conditional_terminal_jump_still_breaks_conditionally(self):
        """
        The other half: when the exiting block really does end in a conditional jump that names a
        second target, the conditional break and its fallthrough to the absent target are unchanged.
        """
        structurer, region, head = _build("condjump")

        assert structurer._refine_cyclic_core(head, {head}) is True

        refined = _refined_exiting_node(region)
        assert isinstance(refined, SequenceNode)
        _, break_node = refined.nodes
        assert isinstance(break_node, ConditionNode)
        assert _jump_targets(break_node.true_node) == [SUCCESSOR]
        assert _jump_targets(break_node.false_node) == [ELSEWHERE]

    def test_an_internal_jump_that_leaves_the_block_is_not_unconditional(self):
        """
        The unconditional break rests on the block's statements, so a conditional jump inside the
        block that targets neither the block itself nor the loop successor takes it away: that path
        leaves the block for somewhere else, and an unconditional break would drop it. Refinement
        refuses as it did before rather than emitting one.
        """
        structurer, _, head = _build("jump", internal_target=ELSEWHERE)

        with self.assertRaises(TypeError):
            structurer._refine_cyclic_core(head, {head})

    def test_a_block_with_code_after_it_is_not_broken_out_of_unconditionally(self):
        """
        The exit edge leaves a graph node, but the break is written at a block found inside it, and
        those differ whenever the node has already been structured. An unconditional break at that
        block's position jumps over everything the node runs afterwards, so refinement refuses when
        the block is not the last thing the node runs -- here a store and a return follow it.
        """
        structurer, _, head = _build("jump", compound=True)

        with self.assertRaises(TypeError):
            structurer._refine_cyclic_core(head, {head})


if __name__ == "__main__":
    unittest.main()
