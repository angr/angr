def slice_callgraph(callgraph, cfg_slice_to_sink):
    """
    Slice a callgraph, keeping only the nodes present in the <CFGSliceToSink> representation, and th transitions for
    which a path exists.

    *Note* that this function mutates the graph passed as an argument.

    :param networkx.MultiDiGraph callgraph:
        The callgraph to update.
    :param CFGSliceToSink cfg_slice_to_sink:
        The representation of the slice, containing the data to update the callgraph from.
    """

    edges_to_remove = list(filter(lambda e: not cfg_slice_to_sink.path_between(*e), callgraph.edges()))

    nodes_to_remove = list(filter(lambda node: node not in cfg_slice_to_sink.nodes, callgraph.nodes()))

    callgraph.remove_edges_from(edges_to_remove)
    callgraph.remove_nodes_from(nodes_to_remove)

    return callgraph


def slice_cfg_graph(graph, cfg_slice_to_sink):
    """
    Slice a CFG graph, keeping only the transitions and nodes present in the <CFGSliceToSink> representation.

    *Note* that this function mutates the graph passed as an argument.

    :param networkx.DiGraph graph: The graph to slice.
    :param CFGSliceToSink cfg_slice_to_sink:
        The representation of the slice, containing the data to update the CFG from.

    :return networkx.DiGraph: The sliced graph.
    """

    def _edge_in_slice_transitions(transitions, edge):
        if edge[0].addr not in transitions.keys():
            return False
        return edge[1].addr in cfg_slice_to_sink.transitions[edge[0].addr]

    edges_to_remove = list(
        filter(lambda edge: not _edge_in_slice_transitions(cfg_slice_to_sink.transitions, edge), graph.edges())
    )

    nodes_to_remove = list(filter(lambda node: node.addr not in cfg_slice_to_sink.nodes, graph.nodes()))

    graph.remove_edges_from(edges_to_remove)
    graph.remove_nodes_from(nodes_to_remove)

    return graph


def slice_function_graph(function_graph, cfg_slice_to_sink):
    """
    Slice a function graph, keeping only the nodes present in the <CFGSliceToSink> representation.

    Because the <CFGSliceToSink> is build from the CFG, and the function graph is *NOT* a subgraph of the CFG, edges of
    the function graph will no be present in the <CFGSliceToSink> transitions.
    However, we use the fact that if there is an edge between two nodes in the function graph, then there must exist
    a path between these two nodes in the slice; Proof idea:
    - The <CFGSliceToSink> is backward and recursively constructed;
    - If a node is in the slice, then all its predecessors will be (transitively);
    - If there is an edge between two nodes in the function graph, there is a path between them in the CFG;
    - So: The origin node is a transitive predecessor of the destination one, hence if destination is in the slice,
    then origin will be too.

    In consequence, in the end, removing the only nodes not present in the slice, and their related transitions gives
    us the expected result: a function graph representing (a higher view of) the flow in the slice.

    *Note* that this function mutates the graph passed as an argument.

    :param networkx.DiGraph graph: The graph to slice.
    :param CFGSliceToSink cfg_slice_to_sink:
        The representation of the slice, containing the data to update the CFG from.

    :return networkx.DiGraph: The sliced graph.
    """

    nodes_to_remove = list(filter(lambda node: node.addr not in cfg_slice_to_sink.nodes, function_graph.nodes()))

    function_graph.remove_nodes_from(nodes_to_remove)

    return function_graph
