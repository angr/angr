import networkx
import nose

from unittest import mock

from angr.analyses.reaching_definitions.dataset import DataSet
from angr.analyses.reaching_definitions.definition import Definition
from angr.analyses.reaching_definitions.def_use_graph import DefUseGraph


def test_def_use_graph_has_a_default_graph():
    def_use_graph = DefUseGraph()
    nose.tools.assert_equal(isinstance(def_use_graph.graph, networkx.DiGraph), True)


def test_def_use_graph_refuses_to_instanciate_with_an_inadequate_graph():
    a_graph = networkx.DiGraph([(1, 2)])
    nose.tools.assert_raises(TypeError, DefUseGraph, a_graph)


def test_refuses_to_add_non_definition_nodes():
    def_use_graph = DefUseGraph()
    nose.tools.assert_raises(TypeError, def_use_graph.add_node, 1)


@mock.patch.object(networkx.DiGraph, 'add_node')
def test_delegate_add_node_to_the_underlying_graph_object(digraph_add_node_mock):
    definition = Definition(None, None, DataSet(set(), 8), None)
    def_use_graph = DefUseGraph()
    def_use_graph.add_node(definition)

    digraph_add_node_mock.assert_called_once_with(definition)


def test_refuses_to_add_edge_between_non_definition_nodes():
    def_use_graph = DefUseGraph()
    nose.tools.assert_raises(TypeError, def_use_graph.add_edge, 1, 2)


@mock.patch.object(networkx.DiGraph, 'add_edge')
def test_delegate_add_edge_to_the_underlying_graph_object(digraph_add_edge_mock):
    use = (
        Definition(None, None, DataSet(set(), 8), None),
        Definition(None, None, DataSet(set(), 8), None),
    )
    def_use_graph = DefUseGraph()
    def_use_graph.add_edge(*use)

    digraph_add_edge_mock.assert_called_once_with(*use)
