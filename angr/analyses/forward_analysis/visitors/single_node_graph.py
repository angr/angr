from .graph import GraphVisitor


class SingleNodeGraphVisitor(GraphVisitor):
    """
    :param node: The single node that should be in the graph.
    """
    def __init__(self, node):
        super(SingleNodeGraphVisitor, self).__init__()
        self.node = node

        self.reset()

    def startpoints(self):
        return [ self.node.addr ]

    def successors(self, node):
        return [ ]

    def predecessors(self, node):
        return [ ]

    def sort_nodes(self, nodes=None):
        if nodes:
            return nodes
        else:
            return [ self.node ]
