from .graph import GraphVisitor


class SingleNodeGraphVisitor(GraphVisitor):
    """
    :param node: The single node that should be in the graph.
    """

    __slots__ = ('node', 'node_returned', )

    def __init__(self, node):
        super(SingleNodeGraphVisitor, self).__init__()
        self.node = node
        self.node_returned = False

    def reset(self):
        self.node_returned = False

    def next_node(self):
        if self.node_returned:
            return None
        self.node_returned = True
        return self.node

    def successors(self, node):
        return [ ]

    def predecessors(self, node):
        return [ ]

    def sort_nodes(self, nodes=None):
        if nodes:
            return nodes
        else:
            return [ self.node ]
