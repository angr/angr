# pylint: disable=no-self-use
import os
from unittest import mock, TestCase

from claripy.utils.orderedset import OrderedSet

from angr.analyses.cfg.cfg_utils import CFGUtils
from angr.analyses.forward_analysis.visitors.cfg import CFGVisitor
from angr.knowledge_plugins.cfg.cfg_node import CFGNode
from angr.project import Project

# disabled since binaries-private is not checked out for angr CI

class TestCFGVisitor(TestCase):
    def setUp(self) -> None:
        binary_path = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', '..', 'binaries-private', 'operation-mango',
            'air-live-bu-2015', 'cgi_test.cgi'
        )
        project = Project(binary_path, auto_load_libs=False)
        cfg = project.analyses.CFGFast()

        self.printf = cfg.kb.functions.function(name='printf', plt=False)
        self.printf_node = cfg.model.get_all_nodes(self.printf.addr)[0]

    def disable_successors_of_a_node_delegate_the_logic_to_the_CFGNode_successor(self):
        with mock.patch.object(CFGVisitor, 'reset'):
            with mock.patch.object(CFGNode, 'successors', new_callable=mock.PropertyMock) as mock_successors:
                addr, size, cfg = 1, None, None
                node = CFGNode(0x42, addr, size, cfg, block_id=1)

                cfg_visitor = CFGVisitor(None)
                _ = cfg_visitor.successors(node)

                mock_successors.assert_called_once_with()

    def disable_predecessors_of_a_node_delegate_the_logic_to_the_CFGNode_predecessor(self):
        with mock.patch.object(CFGVisitor, 'reset'):
            with mock.patch.object(CFGNode, 'predecessors', new_callable=mock.PropertyMock) as mock_predecessors:
                addr, size, cfg = 1, None, None
                node = CFGNode(0x42, addr, size, cfg, block_id=1)

                cfg_visitor = CFGVisitor(None)
                _ = cfg_visitor.predecessors(node)

                mock_predecessors.assert_called_once_with()

    def disable_sort_nodes(self):
        with mock.patch.object(CFGVisitor, 'reset'):
            with mock.patch.object(CFGUtils, 'quasi_topological_sort_nodes') as mock_quasi_topological_sort:
                class CFGVisitorMock(CFGVisitor):
                    def __init__(self, *args):
                        super().__init__(*args)
                        self._cfg = CFGMock()
                    @property
                    def cfg(self):
                        return CFGMock()
                class CFGMock():
                    @property
                    def graph(self):
                        return 'mock_graph_return'

                cfg_visitor = CFGVisitorMock(None)
                _ = cfg_visitor.sort_nodes()

                mock_quasi_topological_sort.assert_called_once_with('mock_graph_return')

    def disable_remove_from_sorted_nodes(self):
        """
        Test the side-effect of a method on an ihnerited private property...
        """

        with mock.patch.object(CFGVisitor, 'reset'):
            cfg_visitor = CFGVisitor(None)

            arbitrarily_chosen_nodes = [self.printf_node] + self.printf_node.predecessors
            cfg_visitor._sorted_nodes = OrderedSet(arbitrarily_chosen_nodes)

            visited_blocks = self.printf_node.predecessors

            cfg_visitor.remove_from_sorted_nodes(visited_blocks)

            self.assertListEqual(list(cfg_visitor._sorted_nodes), [self.printf_node])
