
import networkx  # pylint:disable=unused-import


class AILGraphWalker:
    """
    Walks an AIL graph, and optionally replaces each node with a new node.
    """
    def __init__(self, graph, handler, replace_nodes=False):

        self.graph = graph  # type: networkx.DiGraph
        self.handler = handler
        self._replace_nodes = replace_nodes

    def walk(self):

        for node in list(self.graph.nodes()):
            r = self.handler(node)

            if self._replace_nodes and r is not None:
                in_edges = list(self.graph.in_edges(node, data=True))
                out_edges = list(self.graph.out_edges(node, data=True))

                self.graph.remove_node(node)
                self.graph.add_node(r)

                for src, _, data in in_edges:
                    if src is node:
                        self.graph.add_edge(r, r, data=data)
                    else:
                        self.graph.add_edge(src, r, data=data)

                for _, dst, data in out_edges:
                    if dst is node:
                        self.graph.add_edge(r, r, data=data)
                    else:
                        self.graph.add_edge(r, dst, data=data)
