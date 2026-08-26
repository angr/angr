#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import Const
from angr.ailment.statement import Jump
from angr.analyses.decompiler.region_identifier import RegionIdentifier
from angr.errors import AngrRuntimeError


class TestRegionIdentifierStartNode(unittest.TestCase):
    """
    A function graph can hold more than one node with no in-edges: edges dropped as jump-table debris leave
    source nodes behind, and so does obfuscated control flow. _get_start_node() picked whichever the graph
    happened to iterate first, so the entry could lose the tie-break -- and then everything only the entry
    reaches is unreachable from the region head, which strands whole subregions.
    """

    @staticmethod
    def _block(m, addr):
        return Block(addr, 1, statements=[Jump(m.next_atom(), Const(m.next_atom(), addr + 1, 64), ins_addr=addr)])

    @staticmethod
    def _ri(entry_addr):
        ri = object.__new__(RegionIdentifier)
        ri.entry_node_addr = entry_addr
        return ri

    def test_entry_wins_the_tie_break_against_another_source_node(self):
        m = Manager(arch=None)
        entry, other, body = self._block(m, 0x100), self._block(m, 0x200), self._block(m, 0x300)
        graph = networkx.DiGraph()
        # `other` is inserted first, so iteration reaches it before the entry
        graph.add_edge(other, body)
        graph.add_edge(entry, body)
        assert [n for n in graph if graph.in_degree(n) == 0] == [other, entry]

        assert self._ri((0x100, None))._get_start_node(graph) is entry

    def test_a_sole_source_node_is_still_the_start_node(self):
        m = Manager(arch=None)
        entry, body = self._block(m, 0x100), self._block(m, 0x200)
        graph = networkx.DiGraph()
        graph.add_edge(entry, body)

        assert self._ri((0x100, None))._get_start_node(graph) is entry

    def test_an_entry_with_predecessors_does_not_displace_a_source_node(self):
        m = Manager(arch=None)
        entry, head = self._block(m, 0x100), self._block(m, 0x200)
        graph = networkx.DiGraph()
        # the entry sits inside a loop, so it is not a source: the real source still wins
        graph.add_edge(head, entry)
        graph.add_edge(entry, head)
        graph.add_edge(head, head)
        graph.remove_edge(head, head)
        source = self._block(m, 0x300)
        graph.add_edge(source, head)

        assert self._ri((0x100, None))._get_start_node(graph) is source

    def test_entry_is_the_fallback_when_the_graph_has_no_source_node(self):
        m = Manager(arch=None)
        entry, other = self._block(m, 0x100), self._block(m, 0x200)
        graph = networkx.DiGraph()
        graph.add_edge(entry, other)
        graph.add_edge(other, entry)

        assert self._ri((0x100, None))._get_start_node(graph) is entry

    def test_no_source_node_and_no_entry_still_raises(self):
        m = Manager(arch=None)
        a, b = self._block(m, 0x100), self._block(m, 0x200)
        graph = networkx.DiGraph()
        graph.add_edge(a, b)
        graph.add_edge(b, a)

        with self.assertRaises(AngrRuntimeError):
            self._ri((0x999, None))._get_start_node(graph)


if __name__ == "__main__":
    unittest.main()
