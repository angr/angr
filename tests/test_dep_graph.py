import networkx
import nose

from random import randrange
from unittest import mock

from angr.analyses.code_location import CodeLocation
from angr.analyses.reaching_definitions.dataset import DataSet
from angr.analyses.reaching_definitions.definition import Definition
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


def test_dep_graph_has_a_default_graph():
    dep_graph = DepGraph()
    nose.tools.assert_equal(isinstance(dep_graph.graph, networkx.DiGraph), True)


def test_dep_graph_refuses_to_instanciate_with_an_inadequate_graph():
    a_graph = networkx.DiGraph([(1, 2)])
    nose.tools.assert_raises(TypeError, DepGraph, a_graph)


def test_refuses_to_add_non_definition_nodes():
    dep_graph = DepGraph()
    nose.tools.assert_raises(TypeError, dep_graph.add_node, 1)


@mock.patch.object(networkx.DiGraph, 'add_node')
def test_delegate_add_node_to_the_underlying_graph_object(digraph_add_node_mock):
    definition = _a_mock_definition()
    dep_graph = DepGraph()
    dep_graph.add_node(definition)

    digraph_add_node_mock.assert_called_once_with(definition)


def test_refuses_to_add_edge_between_non_definition_nodes():
    dep_graph = DepGraph()
    nose.tools.assert_raises(TypeError, dep_graph.add_edge, 1, 2)


@mock.patch.object(networkx.DiGraph, 'add_edge')
def test_delegate_add_edge_to_the_underlying_graph_object(digraph_add_edge_mock):
    use = (_a_mock_definition(), _a_mock_definition())
    labels = { 'attribute1': 'value1', 'attribute2': 'value2' }

    dep_graph = DepGraph()
    dep_graph.add_edge(*use, **labels)

    digraph_add_edge_mock.assert_called_once_with(*use, **labels)


def test_top_predecessors():
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

    result = dep_graph.top_predecessors(D)

    nose.tools.assert_list_equal(result, [A, C])


def test_top_predecessors_should_not_contain_duplicates():
    dep_graph = DepGraph()

    # A -> B, A -> C, B -> D, C -> D
    A = _a_mock_definition()
    B = _a_mock_definition()
    C = _a_mock_definition()
    D = _a_mock_definition()
    uses = [
        (A, B),
        (A, C),
        (B, D),
        (C, D),
    ]

    for use in uses:
        dep_graph.add_edge(*use)

    result = dep_graph.top_predecessors(D)

    nose.tools.assert_list_equal(result, [A])


def test_transitive_closure_of_a_node():
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

    nose.tools.assert_set_equal(result_nodes, {D, B, C, A})
    nose.tools.assert_set_equal(result_edges, {(B, D), (C, D), (A, B)})


def test_transitive_closure_of_a_node_should_copy_labels_from_original_graph():
    dep_graph = DepGraph()

    # A -> B
    A = _a_mock_definition()
    B = _a_mock_definition()
    uses = [(A, B)]

    for use in uses:
        dep_graph.add_edge(*use, label='some data')

    result = dep_graph.transitive_closure(B).get_edge_data(A, B)['label']

    nose.tools.assert_equals(result, 'some data')
