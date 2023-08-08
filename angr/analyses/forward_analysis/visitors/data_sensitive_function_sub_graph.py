from angr.utils.graph import GraphUtils
from .graph import GraphVisitor


class DataSensitiveFunctionSubGraphVisitor(GraphVisitor):
    def __init__(self, graph_node_tuple):
        super(DataSensitiveFunctionSubGraphVisitor, self).__init__()
        self.graph = graph_node_tuple[0]
        self.starting_node = graph_node_tuple[1]
        self.reset()

    def successors(self, node):
        return list(self.graph.successors(node))

    def predecessors(self, node):
        return list(self.graph.predecessors(node))

    def sort_nodes(self, nodes=None):
        sorted_nodes = GraphUtils.quasi_topological_sort_nodes(self.graph)

        new_sorted_nodes = []
        reached_starting_node = False
        for node in sorted_nodes:
            if node == self.starting_node or reached_starting_node:
                reached_starting_node = True
                new_sorted_nodes.append(node)

        sorted_nodes = new_sorted_nodes

        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]

        return sorted_nodes
