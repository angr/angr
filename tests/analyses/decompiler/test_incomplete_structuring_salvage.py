#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from typing import TYPE_CHECKING, cast

import networkx

from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import Const
from angr.ailment.statement import Jump, Label
from angr.analyses.decompiler.structurer_nodes import MultiNode, SequenceNode
from angr.analyses.decompiler.structuring.recursive_structurer import RecursiveStructurer

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function
    from angr.project import Project


class _Region:
    """Stands in for a region overlay: the salvage step only reads .graph and .head."""

    def __init__(self, graph, head):
        self.graph = graph
        self.head = head


class _Arch:
    bits = 64


class _Project:
    arch = _Arch()


class _Function:
    def __init__(self, addr):
        self.addr = addr


class TestIncompleteStructuringSalvage(unittest.TestCase):
    """
    When structuring fails to reduce the top-level region to one node, the leftover graph is all that is left of
    the function. Keeping a single node out of it drops the rest of the code, and the jumps into the dropped
    nodes are removed later because their targets are no longer present, so the emitted code falls through edges
    the binary does not have.
    """

    @staticmethod
    def _structurer(func_addr: int | None):
        rs = object.__new__(RecursiveStructurer)
        rs.ail_manager = Manager(arch=None)
        rs.function = None if func_addr is None else cast("Function", _Function(func_addr))
        rs.project = cast("Project", _Project())
        return rs

    @staticmethod
    def _jump_block(m, addr, target):
        return Block(
            addr,
            1,
            statements=[
                Label(m.next_atom(), f"LABEL_{addr:x}", ins_addr=addr),
                Jump(m.next_atom(), Const(m.next_atom(), target, 64), ins_addr=addr),
            ],
        )

    @staticmethod
    def _fallthrough_block(m, addr):
        return Block(
            addr,
            1,
            # a block whose only statement is its label: nothing in it transfers control, so whatever is
            # emitted after it is what runs next
            statements=[Label(m.next_atom(), f"LABEL_{addr:x}", ins_addr=addr)],
        )

    def test_every_leftover_node_is_emitted_in_address_order(self):
        rs = self._structurer(0x100)
        m = rs.ail_manager
        b100 = self._jump_block(m, 0x100, 0x300)
        b200 = self._jump_block(m, 0x200, 0x100)
        b300 = self._jump_block(m, 0x300, 0x200)
        graph = networkx.DiGraph()
        graph.add_edges_from([(b100, b300), (b300, b200), (b200, b100)])

        result = rs._pick_incomplete_result_from_region(_Region(graph, b100))

        assert isinstance(result, SequenceNode)
        assert [node.addr for node in result.nodes] == [0x100, 0x200, 0x300]
        assert result.addr == 0x100

    def test_a_node_that_falls_through_gets_an_explicit_jump_to_its_successor(self):
        rs = self._structurer(0x100)
        m = rs.ail_manager
        b100 = self._jump_block(m, 0x100, 0x300)
        b200 = self._fallthrough_block(m, 0x200)
        b300 = self._jump_block(m, 0x300, 0x200)
        graph = networkx.DiGraph()
        graph.add_edges_from([(b100, b300), (b300, b200), (b200, b100)])

        result = rs._pick_incomplete_result_from_region(_Region(graph, b100))
        assert isinstance(result, SequenceNode)

        # 0x200 falls out of its bottom and its only successor 0x100 is not the node emitted after it, so the
        # transfer is materialised rather than left to the layout
        wrapped = result.nodes[1]
        assert isinstance(wrapped, SequenceNode)
        assert wrapped.nodes[0] is b200
        goto = wrapped.nodes[1]
        assert isinstance(goto, Block)
        assert len(goto.statements) == 1
        assert isinstance(goto.statements[0], Jump)
        assert goto.statements[0].target.value == 0x100

        # ...while 0x300, whose successor 0x200 is emitted next, keeps its own jump and gains nothing
        assert result.nodes[2] is b300

    def test_the_function_entry_is_emitted_first_even_when_it_is_not_the_lowest_address(self):
        rs = self._structurer(0x300)
        m = rs.ail_manager
        b100 = self._jump_block(m, 0x100, 0x300)
        b200 = self._jump_block(m, 0x200, 0x100)
        b300 = self._jump_block(m, 0x300, 0x200)
        graph = networkx.DiGraph()
        graph.add_edges_from([(b300, b200), (b200, b100), (b100, b300)])

        result = rs._pick_incomplete_result_from_region(_Region(graph, b300))

        assert isinstance(result, SequenceNode)
        assert [node.addr for node in result.nodes] == [0x300, 0x100, 0x200]
        assert result.addr == 0x300

    def test_nodes_that_are_not_structurer_nodes_are_kept(self):
        # raw AIL blocks and MultiNodes are the common leaf types of a leftover region graph, and neither is a
        # BaseNode; dropping them loses most of the graph
        rs = self._structurer(0x100)
        m = rs.ail_manager
        b100 = self._jump_block(m, 0x100, 0x200)
        inner_a = self._jump_block(m, 0x200, 0x210)
        inner_b = self._jump_block(m, 0x210, 0x300)
        multi = MultiNode([inner_a, inner_b])
        b300 = self._jump_block(m, 0x300, 0x100)
        graph = networkx.DiGraph()
        graph.add_edges_from([(b100, multi), (multi, b300), (b300, b100)])

        result = rs._pick_incomplete_result_from_region(_Region(graph, b100))

        assert isinstance(result, SequenceNode)
        assert [node.addr for node in result.nodes] == [0x100, 0x200, 0x300]
        assert result.nodes[1] is multi

    def test_a_single_leftover_node_is_returned_unwrapped(self):
        rs = self._structurer(0x100)
        m = rs.ail_manager
        b100 = self._jump_block(m, 0x100, 0x100)
        graph = networkx.DiGraph()
        graph.add_node(b100)

        assert rs._pick_incomplete_result_from_region(_Region(graph, b100)) is b100


if __name__ == "__main__":
    unittest.main()
