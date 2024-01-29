from typing import (
    Optional,
    Dict,
    Set,
    Iterable,
    Type,
    Union,
    List,
    TYPE_CHECKING,
    Tuple,
    overload,
    Literal,
    Any,
    Iterator,
)
from dataclasses import dataclass

import networkx

import claripy
from cle.loader import Loader

from ...code_location import CodeLocation, ExternalCodeLocation
from ...knowledge_plugins.key_definitions.atoms import (
    Atom,
    MemoryLocation,
    AtomKind,
    Register,
    Tmp,
    ConstantSrc,
    GuardUse,
)
from ...knowledge_plugins.key_definitions.definition import A, Definition, DefinitionMatchPredicate
from ...knowledge_plugins.key_definitions.undefined import UNDEFINED
from ...knowledge_plugins.cfg import CFGModel

if TYPE_CHECKING:
    pass


def _is_definition(node):
    return isinstance(node, Definition)


@dataclass
class FunctionCallRelationships:  # TODO this doesn't belong in this file anymore
    callsite: CodeLocation
    target: Optional[int]
    args_defns: List[Set[Definition]]
    other_input_defns: Set[Definition]
    ret_defns: Set[Definition]
    other_output_defns: Set[Definition]


class DepGraph:
    """
    The representation of a dependency graph: a directed graph, where nodes are definitions, and edges represent uses.

    Mostly a wrapper around a <networkx.DiGraph>.
    """

    def __init__(self, graph: Optional["networkx.DiGraph[Definition]"] = None):
        """
        :param graph: A graph where nodes are definitions, and edges represent uses.
        """
        # Used for memoization of the `transitive_closure` method.
        self._transitive_closures: Dict = {}

        if graph and not all(map(_is_definition, graph.nodes)):
            raise TypeError("In a DepGraph, nodes need to be <%s>s." % Definition.__name__)

        self._graph: "networkx.DiGraph[Definition]" = graph if graph is not None else networkx.DiGraph()

    @property
    def graph(self) -> "networkx.DiGraph[Definition]":
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

    def nodes(self) -> "networkx.classes.reportviews.NodeView[Definition]":
        return self._graph.nodes()

    def predecessors(self, node: Definition) -> Iterator[Definition]:
        """
        :param node: The definition to get the predecessors of.
        """
        return self._graph.predecessors(node)

    def transitive_closure(self, definition: Definition[Atom]) -> "networkx.DiGraph[Definition[Atom]]":
        """
        Compute the "transitive closure" of a given definition.
        Obtained by transitively aggregating the ancestors of this definition in the graph.

        Note: Each definition is memoized to avoid any kind of recomputation across the lifetime of this object.

        :param definition:  The Definition to get transitive closure for.
        :return:            A graph of the transitive closure of the given definition.
        """

        def _transitive_closure(
            def_: Definition[Atom],
            graph: "networkx.DiGraph[Definition[Atom]]",
            result: "networkx.DiGraph[Definition[Atom]]",
            visited: Optional[Set[Definition[Atom]]] = None,
        ):
            """
            Returns a joint graph that comprises the transitive closure of all defs that `def_` depends on and the
            current graph `result`. `result` is updated.
            """
            if def_ in self._transitive_closures:
                closure = self._transitive_closures[def_]
                # merge closure into result
                result.add_edges_from(closure.edges())
                return result

            if def_ not in graph:
                return result

            predecessors = list(graph.predecessors(def_))

            result.add_node(def_)
            for pred in predecessors:
                edge_data = graph.get_edge_data(pred, def_)
                if edge_data is None:
                    result.add_edge(pred, def_)
                else:
                    result.add_edge(pred, def_, **edge_data)

            visited = visited or set()
            visited.add(def_)
            predecessors_to_visit = set(predecessors) - set(visited)

            closure = result
            for def0 in predecessors_to_visit:
                closure = _transitive_closure(def0, graph, closure, visited)

            self._transitive_closures[def_] = closure
            return closure

        return _transitive_closure(definition, self._graph, networkx.DiGraph())

    def contains_atom(self, atom: Atom) -> bool:
        return any(map(lambda definition: definition.atom == atom, self.nodes()))

    def add_dependencies_for_concrete_pointers_of(
        self, values: Iterable[Union[claripy.ast.Base, int]], definition: Definition, cfg: CFGModel, loader: Loader
    ):
        """
        When a given definition holds concrete pointers, make sure the <MemoryLocation>s they point to are present in
        the dependency graph; Adds them if necessary.

        :param values:
        :param definition: The definition which has data that can contain concrete pointers.
        :param cfg: The CFG, containing information about memory data.
        :param loader:
        """
        assert definition in self.nodes(), "The given Definition must be present in the given graph."

        known_predecessor_addresses: List[Union[int, claripy.ast.Base]] = list(
            # Needs https://github.com/python/mypy/issues/6847
            map(
                lambda definition: definition.atom.addr,  # type: ignore
                filter(lambda p: isinstance(p.atom, MemoryLocation), self.predecessors(definition)),
            )
        )

        # concretize addresses where possible
        concrete_known_pred_addresses = []
        for address in known_predecessor_addresses:
            if isinstance(address, claripy.ast.Base):
                if address.concrete:
                    concrete_known_pred_addresses.append(address.concrete_value)
            else:
                concrete_known_pred_addresses.append(address)

        unknown_concrete_addresses: Set[int] = set()
        for v in values:
            if isinstance(v, claripy.ast.Base) and v.concrete:
                v = v.concrete_value
            if isinstance(v, int):
                if v not in concrete_known_pred_addresses:
                    unknown_concrete_addresses.add(v)

        for address in unknown_concrete_addresses:
            data_at_address = cfg.memory_data.get(address, None) if cfg is not None else None

            if data_at_address is None or data_at_address.sort not in ["string", "unknown"]:
                continue

            section = loader.main_object.find_section_containing(address)
            read_only = False if section is None else not section.is_writable
            code_location = CodeLocation(0, 0, info={"readonly": True}) if read_only else ExternalCodeLocation()

            def _string_and_length_from(data_at_address):
                if data_at_address.content is None:
                    return UNDEFINED, data_at_address.size
                else:
                    return data_at_address.content.decode("utf-8"), data_at_address.size + 1

            _, string_length = _string_and_length_from(data_at_address)

            memory_location_definition = Definition(
                MemoryLocation(address, string_length),
                code_location,
            )

            self.graph.add_edge(memory_location_definition, definition)

    def find_definitions(self, **kwargs) -> List[Definition]:
        """
        Filter the definitions present in the graph based on various criteria.
        Parameters can be any valid keyword args to `DefinitionMatchPredicate`
        """
        predicate = DefinitionMatchPredicate.construct(**kwargs)
        result = []
        defn: Definition
        for defn in self.nodes():
            if predicate.matches(defn):
                result.append(defn)
        return result

    @overload
    def find_all_predecessors(
        self,
        starts: Union[Definition[Atom], Iterable[Definition[Atom]]],
        *,
        kind: Type[A],
        **kwargs: Any,
    ) -> List[Definition[A]]: ...

    @overload
    def find_all_predecessors(
        self,
        starts: Union[Definition[Atom], Iterable[Definition[Atom]]],
        *,
        kind: Literal[AtomKind.REGISTER] = AtomKind.REGISTER,
        **kwargs: Any,
    ) -> List[Definition[Register]]: ...

    @overload
    def find_all_predecessors(
        self,
        starts: Union[Definition[Atom], Iterable[Definition[Atom]]],
        *,
        kind: Literal[AtomKind.MEMORY] = AtomKind.MEMORY,
        **kwargs: Any,
    ) -> List[Definition[MemoryLocation]]: ...

    @overload
    def find_all_predecessors(
        self,
        starts: Union[Definition[Atom], Iterable[Definition[Atom]]],
        *,
        kind: Literal[AtomKind.TMP] = AtomKind.TMP,
        **kwargs: Any,
    ) -> List[Definition[Tmp]]: ...

    @overload
    def find_all_predecessors(
        self,
        starts: Union[Definition[Atom], Iterable[Definition[Atom]]],
        *,
        kind: Literal[AtomKind.CONSTANT] = AtomKind.CONSTANT,
        **kwargs: Any,
    ) -> List[Definition[ConstantSrc]]: ...

    @overload
    def find_all_predecessors(
        self,
        starts: Union[Definition[Atom], Iterable[Definition[Atom]]],
        *,
        kind: Literal[AtomKind.GUARD] = AtomKind.GUARD,
        **kwargs: Any,
    ) -> List[Definition[GuardUse]]: ...

    @overload
    def find_all_predecessors(
        self,
        starts: Union[Definition[Atom], Iterable[Definition[Atom]]],
        *,
        reg_name: Union[int, str] = ...,
        **kwargs: Any,
    ) -> List[Definition[Register]]: ...

    @overload
    def find_all_predecessors(
        self, starts: Union[Definition[Atom], Iterable[Definition[Atom]]], *, stack_offset: int = ..., **kwargs: Any
    ) -> List[Definition[MemoryLocation]]: ...

    @overload
    def find_all_predecessors(
        self, starts: Union[Definition[Atom], Iterable[Definition[Atom]]], *, const_val: int = ..., **kwargs: Any
    ) -> List[Definition[ConstantSrc]]: ...

    @overload
    def find_all_predecessors(
        self, starts: Union[Definition[Atom], Iterable[Definition[Atom]]], **kwargs: Any
    ) -> List[Definition[Atom]]: ...

    def find_all_predecessors(self, starts, **kwargs):
        """
        Filter the ancestors of the given start node or nodes that match various criteria.
        Parameters can be any valid keyword args to `DefinitionMatchPredicate`
        """
        predicate = DefinitionMatchPredicate.construct(**kwargs)
        result = []
        queue = [starts] if isinstance(starts, Definition) else list(starts)
        seen = set(queue)
        while queue:
            thing = queue.pop()
            try:
                preds = self.graph.pred[thing]
            except KeyError:
                continue
            for pred in preds:
                if pred in seen:
                    continue
                queue.append(pred)
                seen.add(pred)
                if predicate.matches(pred):
                    result.append(pred)
        return result

    def find_all_successors(self, starts: Union[Definition, Iterable[Definition]], **kwargs) -> List[Definition]:
        """
        Filter the descendents of the given start node or nodes that match various criteria.
        Parameters can be any valid keyword args to `DefinitionMatchPredicate`
        """
        predicate = DefinitionMatchPredicate.construct(**kwargs)
        result = []
        queue = [starts] if isinstance(starts, Definition) else list(starts)
        seen = set(queue)
        while queue:
            thing = queue.pop()
            for pred in self.graph.succ[thing]:
                if pred in seen:
                    continue
                queue.append(pred)
                seen.add(pred)
                if predicate.matches(pred):
                    result.append(pred)
        return result

    def find_path(
        self, starts: Union[Definition, Iterable[Definition]], ends: Union[Definition, Iterable[Definition]], **kwargs
    ) -> Optional[Tuple[Definition, ...]]:
        """
        Find a path between the given start node or nodes and the given end node or nodes.
        All the intermediate steps in the path must match the criteria given in kwargs.
        The kwargs can be any valid parameters to `DefinitionMatchPredicate`.

        This algorithm has exponential time and space complexity. Use at your own risk.
        Want to do better? Do it yourself or use networkx and eat the cost of indirection and/or cloning.
        """
        return next(self.find_paths(starts, ends, **kwargs), None)

    def find_paths(
        self, starts: Union[Definition, Iterable[Definition]], ends: Union[Definition, Iterable[Definition]], **kwargs
    ) -> Iterator[Tuple[Definition, ...]]:
        """
        Find all non-overlapping simple paths between the given start node or nodes and the given end node or nodes.
        All the intermediate steps in the path must match the criteria given in kwargs.
        The kwargs can be any valid parameters to `DefinitionMatchPredicate`.

        This algorithm has exponential time and space complexity. Use at your own risk.
        Want to do better? Do it yourself or use networkx and eat the cost of indirection and/or cloning.
        """
        predicate = DefinitionMatchPredicate.construct(**kwargs)
        ends = {ends} if isinstance(ends, Definition) else set(ends)
        queue: List[Tuple[Definition, ...]] = (
            [(starts,)] if isinstance(starts, Definition) else [(start,) for start in starts]
        )
        seen: Set[Definition] = {starts} if isinstance(starts, Definition) else set(starts)
        while queue:
            path = queue.pop()
            for succ in self.graph.succ[path[-1]]:
                newpath = path + (succ,)
                if succ in ends:
                    yield newpath
                elif succ in seen:
                    continue

                seen.add(succ)
                if predicate.matches(succ):
                    queue.append(newpath)
