from typing import Optional, Dict, Set
from functools import reduce

import networkx

from ...knowledge_plugins.key_definitions.definition import Definition


def _is_definition(node):
    return isinstance(node, Definition)


class DepGraph:
    """
    The representation of a dependency graph: a directed graph, where nodes are definitions, and edges represent uses.

    Mostly a wrapper around a <networkx.DiGraph>.
    """

    def __init__(self, graph: Optional[networkx.DiGraph]=None):
        """
        :param graph: A graph where nodes are definitions, and edges represent uses.
        """
        # Used for memoization of the `transitive_closure` method.
        self._transitive_closures: Dict = {}

        if graph and not all(map(_is_definition, graph.nodes)):
            raise TypeError("In a DepGraph, nodes need to be <%s>s." % Definition.__name__)

        self._graph = graph if graph is not None else networkx.DiGraph()

    @property
    def graph(self) -> networkx.DiGraph:
        return self._graph

    def add_node(self, node: Definition) -> None:
        """
        :param node: The definition to add to the definition-use graph.
        """
        if not _is_definition(node):
            raise TypeError("In a DepGraph, nodes need to be <%s>s." % Definition.__name__)

        self._graph.add_node(node)

    def add_edge(self, source: Definition, destination: Definition, **labels) -> None:
        """
        The edge to add to the definition-use graph. Will create nodes that are not yet present.

        :param source: The "source" definition, used by the "destination".
        :param destination: The "destination" definition, using the variable defined by "source".
        :param labels: Optional keyword arguments to represent edge labels.
        """
        if not _is_definition(source) and not _is_definition(destination):
            raise TypeError("In a DepGraph, edges need to be between <%s>s." % Definition.__name__)

        self._graph.add_edge(source, destination, **labels)

    def transitive_closure(self, definition: Definition) -> networkx.DiGraph:
        """
        Compute the "transitive closure" of a given definition.
        Obtained by transitively aggregating the ancestors of this definition in the graph.

        Note: Each definition is memoized to avoid any kind of recomputation across the lifetime of this object.

        :param definition:  The Definition to get transitive closure for.
        :return:            A graph of the transitive closure of the given definition.
        """

        def _transitive_closure(def_: Definition, graph: networkx.DiGraph, result: networkx.DiGraph, visited: Optional[Set[Definition]]=None):
            if def_ in self._transitive_closures.keys():
                return self._transitive_closures[def_]

            predecessors = list(graph.predecessors(def_))

            result.add_node(def_)
            result.add_edges_from(list(map(
                lambda e: (*e, graph.get_edge_data(*e)),
                map(
                    lambda p: (p, def_),
                    predecessors
                )
            )))

            visited = visited or set()
            visited.add(def_)
            predecessors_to_visit = set(predecessors) - set(visited)

            closure = reduce(
                lambda acc, definition: _transitive_closure(definition, graph, acc, visited),
                predecessors_to_visit,
                result
            )

            self._transitive_closures[def_] = closure
            return closure

        return _transitive_closure(definition, self._graph, networkx.DiGraph())
