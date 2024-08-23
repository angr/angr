from __future__ import annotations
import networkx  # pylint:disable=unused-import


class RemoveNodeNotice(Exception):
    pass


class AILGraphWalker:
    """
    Walks an AIL graph and optionally replaces each node with a new node.
    """

    def __init__(self, graph, handler, replace_nodes: bool = False):
        self.graph: networkx.DiGraph = graph
        self.handler = handler
        self._replace_nodes = replace_nodes

    def walk(self):
        for node in list(self.graph.nodes()):
            try:
                r = self.handler(node)
                remove = False
            except RemoveNodeNotice:
                # we need to remove this node
                r = None
                remove = True

            if self._replace_nodes:
                if remove:
                    self.graph.remove_node(node)
                elif r is not None and r is not node:
                    in_edges = list(self.graph.in_edges(node, data=True))
                    out_edges = list(self.graph.out_edges(node, data=True))

                    self.graph.remove_node(node)
                    self.graph.add_node(r)

                    for src, _, data in in_edges:
                        if src is node:
                            self.graph.add_edge(r, r, **data)
                        else:
                            self.graph.add_edge(src, r, **data)

                    for _, dst, data in out_edges:
                        if dst is node:
                            self.graph.add_edge(r, r, **data)
                        else:
                            self.graph.add_edge(r, dst, **data)
