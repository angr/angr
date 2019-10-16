import networkx
import nose

from angr.analyses.slice_to_sink import SliceToSink, slice_graph


class _MockCFGNode():
    def __init__(self, addr):
        self.addr = addr
    def __repr__(self):
        return '%s' % self.addr

def _a_graph_and_its_nodes():
    # Build the following graph (addresses displayed):
    # 0 -> 1, 1 -> 2, 0 -> 3
    graph = networkx.DiGraph()
    nodes = list(map(_MockCFGNode, range(4)))
    graph.add_edge(nodes[0], nodes[1])
    graph.add_edge(nodes[1], nodes[2])
    graph.add_edge(nodes[0], nodes[3])
    return (graph, nodes)


def test_slice_graph_remove_content_not_in_a_slice_to_sink():
    my_graph, nodes = _a_graph_and_its_nodes()

    transitions = {
        nodes[0].addr: [nodes[1].addr],
        nodes[1].addr: [nodes[2].addr]
    }
    my_slice = SliceToSink(None, transitions)

    sliced_graph = slice_graph(my_graph, my_slice)
    result_nodes = list(sliced_graph.nodes)
    result_edges = list(sliced_graph.edges)

    nose.tools.assert_list_equal(result_nodes, [nodes[0], nodes[1], nodes[2]])
    nose.tools.assert_list_equal(result_edges, [(nodes[0], nodes[1]), (nodes[1], nodes[2])])


def test_slice_graph_mutates_the_original_graph():
    my_graph, nodes = _a_graph_and_its_nodes()

    transitions = { nodes[0].addr: [nodes[1].addr] }
    my_slice = SliceToSink(None, transitions)

    sliced_graph = slice_graph(my_graph, my_slice)

    nose.tools.assert_equals(len(my_graph.nodes), 2)
    nose.tools.assert_equals(len(my_graph.edges), 1)
    nose.tools.assert_equals(my_graph, sliced_graph)
