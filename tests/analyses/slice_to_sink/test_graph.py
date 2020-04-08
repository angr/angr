import networkx
import nose

from angr.analyses.slice_to_sink import SliceToSink, slice_callgraph, slice_cfg_graph, slice_function_graph


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


def test_slice_callgraph_remove_content_not_in_a_slice_to_sink():
    my_callgraph, nodes = _a_graph_and_its_nodes()

    # Let's imagine a node (0x42), not a function entry point, not in my_callgraph, such as:
    # 1 -> 0x42, 0x42 -> 2
    transitions = {
        nodes[0]: [nodes[1]],
        nodes[1]: [0x42],
        0x42: [nodes[2]]
    }
    slice_to_sink = SliceToSink(None, transitions)

    sliced_callgraph = slice_callgraph(my_callgraph, slice_to_sink)

    result_nodes = list(sliced_callgraph.nodes)
    result_edges = list(sliced_callgraph.edges)

    nose.tools.assert_list_equal(result_nodes, [nodes[0], nodes[1], nodes[2]])
    nose.tools.assert_list_equal(result_edges, [(nodes[0], nodes[1]), (nodes[1], nodes[2])])


def test_slice_callgraph_mutates_the_original_graph():
    my_callgraph, nodes = _a_graph_and_its_nodes()

    # Let's imagine a node (0x42), not a function entry point, not in my_callgraph, such as:
    # 1 -> 0x42, 0x42 -> 2
    transitions = {
        nodes[0]: [nodes[1]],
        nodes[1]: [0x42],
        0x42: [nodes[2]]
    }
    slice_to_sink = SliceToSink(None, transitions)

    sliced_callgraph = slice_callgraph(my_callgraph, slice_to_sink)

    nose.tools.assert_equals(len(my_callgraph.nodes), 3)
    nose.tools.assert_equals(len(my_callgraph.edges), 2)
    nose.tools.assert_equals(my_callgraph, sliced_callgraph)


def test_slice_cfg_graph_remove_content_not_in_a_slice_to_sink():
    my_graph, nodes = _a_graph_and_its_nodes()

    transitions = {
        nodes[0].addr: [nodes[1].addr],
        nodes[1].addr: [nodes[2].addr]
    }
    my_slice = SliceToSink(None, transitions)

    sliced_graph = slice_cfg_graph(my_graph, my_slice)
    result_nodes = list(sliced_graph.nodes)
    result_edges = list(sliced_graph.edges)

    nose.tools.assert_list_equal(result_nodes, [nodes[0], nodes[1], nodes[2]])
    nose.tools.assert_list_equal(result_edges, [(nodes[0], nodes[1]), (nodes[1], nodes[2])])


def test_slice_cfg_graph_mutates_the_original_graph():
    my_graph, nodes = _a_graph_and_its_nodes()

    transitions = { nodes[0].addr: [nodes[1].addr] }
    my_slice = SliceToSink(None, transitions)

    sliced_graph = slice_cfg_graph(my_graph, my_slice)

    nose.tools.assert_equals(len(my_graph.nodes), 2)
    nose.tools.assert_equals(len(my_graph.edges), 1)
    nose.tools.assert_equals(my_graph, sliced_graph)


def test_slice_function_graph_remove_nodes_not_in_a_slice_to_sink():
    # Imagine a CFG being:    0 -> 0x42, 0x42 -> 1, 1 -> 2, 0 -> 3
    # And the function graph: 0 -> 1, 1 -> 2, 0 -> 3
    my_function_graph, nodes = _a_graph_and_its_nodes()

    transitions = { nodes[0].addr: [0x42], 0x42: [nodes[1].addr] }
    my_slice = SliceToSink(None, transitions)

    sliced_function_graph = slice_function_graph(my_function_graph, my_slice)
    result_nodes = list(sliced_function_graph.nodes)
    result_edges = list(sliced_function_graph.edges)

    nose.tools.assert_list_equal(result_nodes, [nodes[0], nodes[1]])
    nose.tools.assert_list_equal(result_edges, [(nodes[0], nodes[1])])


def test_slice_function_graph_mutates_the_original_function_graph():
    # Imagine a CFG being:    0 -> 0x42, 0x42 -> 1, 1 -> 2, 0 -> 3
    # And the function graph: 0 -> 1, 1 -> 2, 0 -> 3
    my_function_graph, nodes = _a_graph_and_its_nodes()

    transitions = { nodes[0].addr: [0x42], 0x42: [nodes[1].addr] }
    my_slice = SliceToSink(None, transitions)

    sliced_function_graph = slice_function_graph(my_function_graph, my_slice)

    nose.tools.assert_equals(len(my_function_graph.nodes), 2)
    nose.tools.assert_equals(len(my_function_graph.edges), 1)
    nose.tools.assert_equals(my_function_graph, sliced_function_graph)
