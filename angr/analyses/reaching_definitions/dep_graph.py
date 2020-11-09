from typing import Optional, Dict, Set
from functools import reduce

import networkx

from cle.loader import Loader

from ...code_location import CodeLocation
from ...knowledge_plugins.key_definitions.atoms import Atom, MemoryLocation
from ...knowledge_plugins.key_definitions.dataset import DataSet
from ...knowledge_plugins.key_definitions.definition import Definition
from ...knowledge_plugins.key_definitions.undefined import UNDEFINED
from ..cfg.cfg_base import CFGBase
from .external_codeloc import ExternalCodeLocation


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
        self._graph.add_node(node)

    def add_edge(self, source: Definition, destination: Definition, **labels) -> None:
        """
        The edge to add to the definition-use graph. Will create nodes that are not yet present.

        :param source: The "source" definition, used by the "destination".
        :param destination: The "destination" definition, using the variable defined by "source".
        :param labels: Optional keyword arguments to represent edge labels.
        """
        self._graph.add_edge(source, destination, **labels)

    def nodes(self) -> networkx.classes.reportviews.NodeView: return self._graph.nodes()

    def predecessors(self, node: Definition) -> networkx.classes.reportviews.NodeView:
        """
        :param node: The definition to get the predecessors of.
        """
        return self._graph.predecessors(node)


    def transitive_closure(self, definition: Definition) -> networkx.DiGraph:
        """
        Compute the "transitive closure" of a given definition.
        Obtained by transitively aggregating the ancestors of this definition in the graph.

        Note: Each definition is memoized to avoid any kind of recomputation across the lifetime of this object.

        :param definition:  The Definition to get transitive closure for.
        :return:            A graph of the transitive closure of the given definition.
        """

        def _transitive_closure(def_: Definition, graph: networkx.DiGraph, result: networkx.DiGraph,
                                visited: Optional[Set[Definition]]=None):
            """
            Returns a joint graph that comprises the transitive closure of all defs that `def_` depends on and the
            current graph `result`. `result` is updated.
            """
            if def_ in self._transitive_closures.keys():
                closure = self._transitive_closures[def_]
                # merge closure into result
                result.add_edges_from(closure.edges())
                return result

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
                lambda acc, def0: _transitive_closure(def0, graph, acc, visited),
                predecessors_to_visit,
                result
            )

            self._transitive_closures[def_] = closure
            return closure

        return _transitive_closure(definition, self._graph, networkx.DiGraph())

    def contains_atom(self, atom: Atom) -> bool:
        return any(map(
            lambda definition: definition.atom == atom,
            self.nodes()
        ))

    def add_dependencies_for_concrete_pointers_of(self, definition: Definition, cfg: CFGBase, loader: Loader):
        """
        When a given definition holds concrete pointers, make sure the <MemoryLocation>s they point to are present in the
        dependency graph; Adds them if necessary.

        :param definition: The definition which has data that can contain concrete pointers.
        :param cfg: The CFG, containing informations about memory data.
        """
        assert definition in self.nodes(), 'The given Definition must be present in the given graph.'

        known_predecessor_addresses = list(map(
            lambda definition: definition.atom.addr,
            filter(
                lambda p: isinstance(p.atom, MemoryLocation),
                self.predecessors(definition)
            )
        ))

        unknown_concrete_addresses = list(filter(
            lambda address: isinstance(address, int) and address not in known_predecessor_addresses,
            definition.data
        ))

        for address in unknown_concrete_addresses:
            data_at_address = cfg.memory_data.get(address, None)

            if data_at_address is None or data_at_address.sort not in ['string', 'unknown']: continue

            section = loader.main_object.find_section_containing(address)
            read_only = False if section is None else not section.is_writable
            code_location = \
                CodeLocation(0, 0, info={'readonly': True}) if read_only else ExternalCodeLocation()

            def _string_and_length_from(data_at_address):
                if data_at_address.content is None:
                    return (UNDEFINED, data_at_address.size)
                else:
                    return (data_at_address.content.decode('utf-8'), data_at_address.size + 1)
            pointed_string, string_length = _string_and_length_from(data_at_address)

            memory_location_definition = Definition(
                MemoryLocation(address, string_length),
                code_location,
                DataSet(pointed_string, string_length * 8)
            )

            self.graph.add_edge(memory_location_definition, definition)
