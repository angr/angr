import networkx

from .definition import Definition


def _is_definition(node):
    return isinstance(node, Definition)


class DefUseGraph:
    """
    The representation of a definition-use graph: a directed graph, where nodes are definitions, and edges represent uses.

    Mostly a wrapper around a <networkx.DiGraph>.
    """

    def __init__(self, graph=None):
        """
        :param networkx.DiGraph graph: A graph where nodes are definitions, and edges represent uses.
        """
        if not isinstance(graph, networkx.DiGraph):
            self._graph = networkx.DiGraph()
            return

        if not all(map(_is_definition, graph.nodes)):
            raise TypeError("In a DefUseGraph, nodes need to be <%s>s." % Definition.__name__)

        self._graph = graph

    @property
    def graph(self):
        return self._graph

    def add_node(self, node):
        """
        :param Definition node: The definition to add to the definition-use graph.
        """
        if not _is_definition(node):
            raise TypeError("In a DefUseGraph, nodes need to be <%s>s." % Definition.__name__)

        self._graph.add_node(node)

    def add_edge(self, source, destination):
        """
        The edge to add to the definition-use graph. Will create nodes that are not yet present.

        :param Definition source: The "source" definition, used by the "destination".
        :param Definition destination: The "destination" definition, using the variable defined by "source".
        """
        if not _is_definition(source) and not _is_definition(destination):
            raise TypeError("In a DefUseGraph, edges need to be between <%s>s." % Definition.__name__)

        self._graph.add_edge(source, destination)
