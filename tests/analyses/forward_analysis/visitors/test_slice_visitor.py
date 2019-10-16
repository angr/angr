# pylint: disable=no-self-use
import os
from unittest import mock

import nose

from angr.analyses.cfg.cfg_base import CFGBase
from angr.analyses.cfg.cfg_utils import CFGUtils
from angr.analyses.forward_analysis.visitors.slice import SliceVisitor
from angr.analyses.slice_to_sink import SliceToSink
from angr.knowledge_plugins.cfg.cfg_node import CFGNode
from angr.project import Project
from claripy.utils.orderedset import OrderedSet


BINARIES_PATH = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', '..', '..', '..', 'binaries-private', 'operation-mango'
)
BINARY_PATH = os.path.join(BINARIES_PATH, 'air-live-bu-2015', 'cgi_test.cgi')
PROJECT = Project(BINARY_PATH, auto_load_libs=False)
CFG = PROJECT.analyses.CFGFast()
PRINTF = CFG.kb.functions.function(name='printf', plt=False)
PRINTF_NODE = CFG.model.get_all_nodes(PRINTF.addr)[0]


# `reset` is called at each `__init__` and calls `sort_nodes` which lacks a good CFG mock to properly work.
@mock.patch.object(SliceVisitor, 'reset')
class TestSliceVisitor():
    def test_sucessors_of_a_node(self, _):
        """
        Test the "private" method `_successors` to focus on our representation.
        `successors` returns a CFGNode and requires a valid `CFG` to operate, which is beyond the scope of this test.
        """
        addr, size, cfg = 1, None, None
        node = CFGNode(0x42, addr, size, cfg, block_id=1)
        slice_to_visit = SliceToSink(None, {
            node.addr: [0x43, 0x44, 0x45],
        })
        slice_visitor = SliceVisitor(slice_to_visit, None)

        successors = list(slice_visitor._successors(node))
        nose.tools.assert_list_equal(successors, [0x43, 0x44, 0x45])


    def test_successors_of_bottom_node(self, _):
        """
        Test the "private" method `_successors` to focus on our representation.
        `successors` returns a CFGNode and requires a valid `CFG` to operate, which is beyond the scope of this test.
        """
        addr, size, cfg = 1, None, None
        node = CFGNode(0x42, addr, size, cfg, block_id=1)

        slice_to_visit = SliceToSink(None, {
            0x41: [node.addr],
        })
        slice_visitor = SliceVisitor(slice_to_visit, None)

        successors = list(slice_visitor._successors(node))
        nose.tools.assert_equal(successors, [])


    def test_predecessors_of_a_node(self, _):
        """
        Test the "private" method `_predecessors` to focus on our representation.
        `predecessors` returns a CFGNode and requires a valid `CFG` to operate, which is beyond the scope of this test.
        """
        addr, size, cfg = 1, None, None
        node = CFGNode(0x42, addr, size, cfg, block_id=1)
        slice_to_visit = SliceToSink(None, {
            0x40: [node.addr],
            0x41: [node.addr, 0x43],
        })
        slice_visitor = SliceVisitor(slice_to_visit, None)

        predecessors = list(slice_visitor._predecessors(node))
        nose.tools.assert_list_equal(predecessors, [0x40, 0x41])


    def test_predecessors_of_top_node(self, _):
        """
        Test the "private" method `_predecessors` to focus on our representation.
        `predecessors` returns a CFGNode and requires a valid `CFG` to operate, which is beyond the scope of this test.
        """
        addr, size, cfg = 1, None, None
        node = CFGNode(0x42, addr, size, cfg, block_id=1)
        slice_to_visit = SliceToSink(None, {
            node.addr: [0x43],
        })
        slice_visitor = SliceVisitor(slice_to_visit, None)

        predecessors = list(slice_visitor._predecessors(node))
        nose.tools.assert_equal(predecessors, [])


    @mock.patch.object(CFGUtils, 'quasi_topological_sort_nodes')
    def test_sort_nodes(self, mock_quasi_topological_sort, _):
        class SliceVisitorMock(SliceVisitor):
            @property
            def cfg(self):
                return CFGMock()
        class CFGMock():
            @property
            def graph(self):
                return 'mock_graph_return'

        slice_visitor = SliceVisitorMock({}, None)
        _ = slice_visitor.sort_nodes()

        mock_quasi_topological_sort.assert_called_once_with('mock_graph_return')


    def test_compute_cfg_of_the_slice_from_original_cfg(self, _):
        slice_to_visit = SliceToSink(PRINTF, {
            PRINTF_NODE.predecessors[0].addr: [PRINTF_NODE.addr],
        })
        slice_visitor = SliceVisitor(slice_to_visit, CFG)

        slice_cfg = slice_visitor.cfg

        nose.tools.assert_equal(isinstance(slice_cfg, CFGBase), True)
        nose.tools.assert_equal(len(slice_cfg.graph.edges), 1)
        nose.tools.assert_equal(len(slice_cfg.graph.nodes), 2)


    def test_remove_from_sorted_nodes(self, _):
        """
        Test the side-effect of a method on an ihnerited private property...
        """
        slice_visitor = SliceVisitor(None, None)

        arbitrarily_chosen_nodes = [PRINTF_NODE] + PRINTF_NODE.predecessors
        slice_visitor._sorted_nodes = OrderedSet(arbitrarily_chosen_nodes)

        visited_blocks = PRINTF_NODE.predecessors

        slice_visitor.remove_from_sorted_nodes(visited_blocks)

        nose.tools.assert_list_equal(list(slice_visitor._sorted_nodes), [PRINTF_NODE])
