#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.ailment import Block
from angr.ailment.expression import Const
from angr.ailment.statement import Jump, Label, Return
from angr.analyses.decompiler.optimization_passes.return_duplicator_base import ReturnDuplicatorBase


def _label(addr):
    return Label(0, f"LABEL_{addr:x}", ins_addr=addr, block_idx=None)


class TestReturnDuplicatorStatementlessGraph(unittest.TestCase):
    """
    An AIL block in a decompilation graph may carry no statements: graph recovery emits a zero-size block
    for a fall-through that no instruction backs, and Clinic drops empty nodes only once every stage has
    run. _is_simple_return_graph strips labels before it looks, so such a block leaves it nothing at all.
    """

    def test_a_graph_whose_nodes_hold_no_statements_is_not_a_return_graph(self):
        # the label is the block's only statement, and remove_labels() takes it away
        block = Block(0x400100, 0, statements=[_label(0x400100)])
        graph = networkx.DiGraph()
        graph.add_node(block)

        # no statements means no return statement
        assert ReturnDuplicatorBase._is_simple_return_graph(graph) is False

    def test_a_statementless_block_ahead_of_a_return_is_still_a_return_graph(self):
        # the new check must reject only graphs that hold nothing, not graphs that merely start empty
        empty = Block(0x400100, 0, statements=[_label(0x400100)])
        returns = Block(0x400104, 1, statements=[_label(0x400104), Return(0, [], ins_addr=0x400104)])
        graph = networkx.DiGraph()
        graph.add_edge(empty, returns)

        assert ReturnDuplicatorBase._is_simple_return_graph(graph) is True

    def test_a_jump_only_graph_is_still_rejected(self):
        block = Block(0x400100, 2, statements=[_label(0x400100), Jump(0, Const(1, 0x400200, 32), ins_addr=0x400100)])
        graph = networkx.DiGraph()
        graph.add_node(block)

        assert ReturnDuplicatorBase._is_simple_return_graph(graph) is False


if __name__ == "__main__":
    unittest.main()
