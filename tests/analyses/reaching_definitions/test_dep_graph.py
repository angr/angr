# pylint: disable=no-self-use
from random import randrange
from unittest import mock, TestCase
import networkx


from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.dataset import DataSet
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.analyses.reaching_definitions.dep_graph import DepGraph


_PAST_N = set()


def unique_randrange(range_):
    n = randrange(range_)
    while n in _PAST_N:
        n = randrange(range_)
    _PAST_N.add(n)
    return n


def _a_mock_definition():
    # Randomise code locations to forcefully produce "different" <Definition>s.
    statement_index = unique_randrange(1000)
    code_location = CodeLocation(0x42, statement_index)
    return Definition(None, code_location, DataSet(set(), 8), None)


class TestDepGraph(TestCase):
    def test_dep_graph_has_a_default_graph(self):
        dep_graph = DepGraph()
        self.assertEqual(isinstance(dep_graph.graph, networkx.DiGraph), True)

    def test_dep_graph_refuses_to_instanciate_with_an_inadequate_graph(self):
        a_graph = networkx.DiGraph([(1, 2)])
        self.assertRaises(TypeError, DepGraph, a_graph)

    def test_refuses_to_add_non_definition_nodes(self):
        dep_graph = DepGraph()
        self.assertRaises(TypeError, dep_graph.add_node, 1)

    def test_delegate_add_node_to_the_underlying_graph_object(self):
        with mock.patch.object(networkx.DiGraph, 'add_node') as digraph_add_node_mock:
            definition = _a_mock_definition()
            dep_graph = DepGraph()
            dep_graph.add_node(definition)

            digraph_add_node_mock.assert_called_once_with(definition)

    def test_refuses_to_add_edge_between_non_definition_nodes(self):
        dep_graph = DepGraph()
        self.assertRaises(TypeError, dep_graph.add_edge, 1, 2)

    def test_delegate_add_edge_to_the_underlying_graph_object(self):
        with mock.patch.object(networkx.DiGraph, 'add_edge') as digraph_add_edge_mock:
            use = (_a_mock_definition(), _a_mock_definition())
            labels = { 'attribute1': 'value1', 'attribute2': 'value2' }

            dep_graph = DepGraph()
            dep_graph.add_edge(*use, **labels)

            digraph_add_edge_mock.assert_called_once_with(*use, **labels)

    def test_transitive_closure_of_a_node(self):
        dep_graph = DepGraph()

        # A -> B, B -> D, C -> D
        A = _a_mock_definition()
        B = _a_mock_definition()
        C = _a_mock_definition()
        D = _a_mock_definition()
        uses = [
            (A, B),
            (B, D),
            (C, D),
        ]

        for use in uses:
            dep_graph.add_edge(*use)

        result = dep_graph.transitive_closure(D)
        result_nodes = set(result.nodes)
        result_edges = set(result.edges)

        self.assertSetEqual(result_nodes, {D, B, C, A})
        self.assertSetEqual(result_edges, {(B, D), (C, D), (A, B)})

    def test_transitive_closure_includes_beginning_node_with_memoized_content(self):
        dep_graph = DepGraph()
        # A -> B
        # B -> C
        # C -> D
        A = _a_mock_definition()
        B = _a_mock_definition()
        C = _a_mock_definition()
        D = _a_mock_definition()
        uses = [
            (A, B),
            (B, C),
            (C, D)
        ]
        for use in uses:
            dep_graph.add_edge(*use)

        closure_0 = dep_graph.transitive_closure(C)
        self.assertNotIn(D, closure_0)

        closure_1 = dep_graph.transitive_closure(D)
        self.assertIn(D, closure_1)
        self.assertTrue(closure_1.has_edge(A, B))
        self.assertTrue(closure_1.has_edge(B, C))
        self.assertTrue(closure_1.has_edge(C, D))

    def test_transitive_closure_of_a_node_should_copy_labels_from_original_graph(self):
        dep_graph = DepGraph()

        # A -> B
        A = _a_mock_definition()
        B = _a_mock_definition()
        uses = [(A, B)]

        for use in uses:
            dep_graph.add_edge(*use, label='some data')

        result = dep_graph.transitive_closure(B).get_edge_data(A, B)['label']

        self.assertEqual(result, 'some data')

    def test_transitive_closure_of_a_node_on_a_graph_with_loops_should_still_terminate(self):
        dep_graph = DepGraph()

        # A -> B, B -> C, C -> D, D -> A
        A = _a_mock_definition()
        B = _a_mock_definition()
        C = _a_mock_definition()
        D = _a_mock_definition()
        uses = [
            (A, B),
            (B, C),
            (C, D),
            (D, A),
        ]

        for use in uses:
            dep_graph.add_edge(*use)

        result = dep_graph.transitive_closure(C)
        result_nodes = set(result.nodes)
        result_edges = set(result.edges)

        self.assertSetEqual(result_nodes, {A, B, C, D})
        self.assertSetEqual(result_edges, {(A, B), (B, C), (C, D), (D, A)})
