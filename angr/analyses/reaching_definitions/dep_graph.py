import networkx

from functools import reduce

from .definition import Definition


def _is_definition(node):
    return isinstance(node, Definition)


class DepGraph:
    """
    The representation of a dependency graph: a directed graph, where nodes are definitions, and edges represent uses.

    Mostly a wrapper around a <networkx.DiGraph>.
    """

    def __init__(self, graph=None):
        """
        :param networkx.DiGraph graph: A graph where nodes are definitions, and edges represent uses.
        """
        # Used for memoization of the `transitive_closure` method.
        self._transitive_closures = {}

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

    def add_edge(self, source, destination, **labels):
        """
        The edge to add to the definition-use graph. Will create nodes that are not yet present.

        :param Definition source: The "source" definition, used by the "destination".
        :param Definition destination: The "destination" definition, using the variable defined by "source".
        :param labels: Optional keyword arguments to represent edge labels.
        """
        if not _is_definition(source) and not _is_definition(destination):
            raise TypeError("In a DefUseGraph, edges need to be between <%s>s." % Definition.__name__)

        self._graph.add_edge(source, destination, **labels)

    def transitive_closure(self, definition):
        """
        Compute the "transitive closure" of a given definition.
        Obtained by transitively aggregating the ancestors of this definition in the graph.

        Note: Each definition is memoized to avoid any kind of recomputation accross the lifetime of this object.

        :param Definition definition: The <Definition> to return the top-level ancestors for.
        :return List[Definition]: The list of top-level definitions flowing into the <node>.
        """

        def _transitive_closure(definition, graph, result=None):
            if definition in self._transitive_closures.keys():
                return self._transitive_closures[definition]

            predecessors = list(graph.predecessors(definition))

            result.add_node(definition)
            result.add_edges_from(list(map(
                lambda e: (*e, graph.get_edge_data(*e)),
                map(
                    lambda p: (p, definition),
                    predecessors
                )
            )))

            closure = reduce(
                lambda acc, definition: _transitive_closure(definition, graph, acc),
                predecessors,
                result
            )

            self._transitive_closures[definition] = closure
            return closure

        return _transitive_closure(definition, self._graph, networkx.DiGraph())

    def top_predecessors(self, definition):
        """
        Recover the "entrypoint definitions" flowing into a given definition.
        Obtained by transitively computing the top-level ancestors (nodes without predecessors) of this definition in
        the graph.

        :param Definition definition: The <Definition> to return the top-level ancestors for.
        :return List[Definition]: The list of top-level definitions flowing into the <node>.
        """

        def _top_predecessors(definition, graph, result):
            predecessors = list(graph.predecessors(definition))

            if len(predecessors) == 0 and definition not in result:
                return result + [ definition ]

            return reduce(
                lambda acc, definition: _top_predecessors(definition, graph, acc),
                predecessors,
                result
            )

        return _top_predecessors(definition, self._graph, [])
