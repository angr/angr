# The mixin deliberately selects the concrete NetworkX superclass inside deferred mutation closures.
# pylint:disable=missing-class-docstring,no-self-use,protected-access,super-with-arguments,useless-object-inheritance
from __future__ import annotations

import itertools
import weakref
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

import networkx  # pyright: ignore[reportMissingModuleSource]

_MISSING = object()
_NodeInsertionCallback = Callable[[Any], Callable[[], None] | None]


class _MutationCallback:
    def __init__(self, callback: Callable[..., Any] | None):
        if callback is None:
            self._callback = None
        else:
            try:
                self._callback = weakref.WeakMethod(callback)
            except TypeError:
                self._callback = weakref.ref(callback)

    def __call__(self, *args) -> Any:
        if self._callback is not None and (callback := self._callback()) is not None:
            return callback(*args)
        return None

    @property
    def alive(self) -> bool:
        return self._callback is not None and self._callback() is not None


class _ObservableDict(dict):
    def __init__(self, *args, mutation_callback: Callable[[], None] | None = None, **kwargs):
        self._mutation_callback = _MutationCallback(None)
        self._mutation_depth = 0
        self._mutation_pending = False
        super().__init__(*args, **kwargs)
        self._mutation_callback = _MutationCallback(mutation_callback)

    def set_mutation_callback(self, callback: Callable[[], None] | None) -> None:
        self._mutation_callback = _MutationCallback(callback)

    def _notify(self) -> None:
        if self._mutation_depth:
            self._mutation_pending = True
        else:
            self._mutation_callback()

    @contextmanager
    def _coalesce_mutations(self):
        outermost = self._mutation_depth == 0
        baseline = dict(self) if outermost else None
        failed = False
        self._mutation_depth += 1
        try:
            yield
        except BaseException:
            failed = True
            raise
        finally:
            if outermost and self._mutation_pending:
                self._mutation_pending = False
                if failed:
                    changed = True
                else:
                    try:
                        changed = baseline != dict(self)
                    except Exception:  # pylint:disable=broad-except
                        changed = True
                    else:
                        # Equality itself may invoke hostile user code that mutates this dictionary.
                        changed |= self._mutation_pending
                self._mutation_pending = changed
            self._mutation_depth -= 1
            if outermost and self._mutation_pending:
                self._mutation_pending = False
                self._mutation_callback()

    @staticmethod
    def _values_equal(old_value, new_value) -> bool:
        if old_value is new_value:
            return True
        try:
            return bool(old_value == new_value)
        except Exception:  # pylint:disable=broad-except
            return False

    def __setitem__(self, key, value) -> None:
        with self._coalesce_mutations():
            old_value = self.get(key, _MISSING)
            changed = old_value is _MISSING or not self._values_equal(old_value, value)
            super().__setitem__(key, value)
            if changed:
                self._notify()

    def __delitem__(self, key) -> None:
        super().__delitem__(key)
        self._notify()

    def clear(self) -> None:
        if self:
            super().clear()
            self._notify()

    def pop(self, key, default=_MISSING):
        if key in self:
            value = super().pop(key)
            self._notify()
            return value
        if default is _MISSING:
            raise KeyError(key)
        return default

    def popitem(self):
        item = super().popitem()
        self._notify()
        return item

    def setdefault(self, key, default=None):
        if key in self:
            return self[key]
        value = super().setdefault(key, default)
        self._notify()
        return value

    def update(self, *args, **kwargs) -> None:
        if len(args) > 1:
            raise TypeError(f"update expected at most 1 argument, got {len(args)}")

        changed = False

        def set_item(key, value):
            nonlocal changed
            old_value = self.get(key, _MISSING)
            changed |= old_value is _MISSING or not self._values_equal(old_value, value)
            super(_ObservableDict, self).__setitem__(key, value)

        with self._coalesce_mutations():
            try:
                if args:
                    other = args[0]
                    if hasattr(other, "keys"):
                        # Match dict.update()'s support for mapping-like objects that provide keys() without __iter__.
                        for key in other.keys():  # noqa: SIM118
                            set_item(key, other[key])
                    else:
                        for key, value in other:
                            set_item(key, value)
                for key, value in kwargs.items():
                    set_item(key, value)
            finally:
                if changed:
                    self._notify()

    def __ior__(self, other):
        self.update(other)
        return self

    def __reduce__(self):
        return type(self), (dict(self),)


class _ObservableGraphMixin(networkx.DiGraph if TYPE_CHECKING else object):
    # Function/CC summary semantics consume graph topology and edge metadata. NetworkX's graph-level and node-level
    # attribute dictionaries remain ordinary presentation/annotation storage and are intentionally not observable.
    _mutation_callback: _MutationCallback
    _node_validation_callback: _MutationCallback
    _node_insertion_callback: _MutationCallback
    _mutation_depth: int
    _mutation_pending: bool
    _mutation_serial: int
    _node: dict[Any, Any]
    _succ: dict[Any, Any]
    _pred: dict[Any, Any]
    edges: Any
    out_edges: Any
    in_edges: Any

    def __init__(
        self,
        incoming_graph_data=None,
        *,
        mutation_callback: Callable[[], None] | None = None,
        node_validation_callback: Callable[[Any], None] | None = None,
        node_insertion_callback: _NodeInsertionCallback | None = None,
        **attr,
    ):
        self._mutation_callback = _MutationCallback(None)
        self._node_validation_callback = _MutationCallback(None)
        self._node_insertion_callback = _MutationCallback(None)
        self._mutation_depth = 0
        self._mutation_pending = False
        self._mutation_serial = 0
        super().__init__(incoming_graph_data, **attr)
        self.set_mutation_callback(mutation_callback)
        self.set_node_validation_callback(node_validation_callback)
        self.set_node_insertion_callback(node_insertion_callback)

    def edge_attr_dict_factory(self):
        # NetworkX populates a newly-created edge attribute dictionary before linking it into adjacency. Keep it
        # detached until the corresponding add operation succeeds so a partially-consumed hostile attribute iterable
        # cannot report a mutation for an edge that was never installed.
        return _ObservableDict()

    def _capture_mutation_callback_state(self):
        callback_state = self._mutation_callback
        edge_callback_states = {}
        for _, _, data in self.edges(data=True):
            if isinstance(data, _ObservableDict):
                edge_callback_states.setdefault(id(data), (data, data._mutation_callback))
        return callback_state, tuple(edge_callback_states.values())

    def _restore_mutation_callback_state(self, state) -> None:
        callback_state, edge_callback_states = state
        self._mutation_callback = callback_state
        for data, edge_callback_state in edge_callback_states:
            data._mutation_callback = edge_callback_state

    def _prepare_mutation_callback(self, callback: Callable[[], None] | None) -> _MutationCallback:
        new_callback = _MutationCallback(callback)
        old_state = self._capture_mutation_callback_state()
        try:
            for data, _ in old_state[1]:
                data.set_mutation_callback(self._graph_mutated)
        except Exception:
            self._restore_mutation_callback_state(old_state)
            raise
        return new_callback

    @staticmethod
    def _prepare_node_callbacks(
        validation_callback: Callable[[Any], None] | None,
        insertion_callback: _NodeInsertionCallback | None,
    ) -> tuple[_MutationCallback, _MutationCallback]:
        return _MutationCallback(validation_callback), _MutationCallback(insertion_callback)

    def set_mutation_callback(self, callback: Callable[[], None] | None) -> None:
        self._mutation_callback = self._prepare_mutation_callback(callback)

    def set_node_validation_callback(self, callback: Callable[[Any], None] | None) -> None:
        self._node_validation_callback = _MutationCallback(callback)

    def set_node_insertion_callback(self, callback: _NodeInsertionCallback | None) -> None:
        self._node_insertion_callback = _MutationCallback(callback)

    def _validate_node_insertion(self, node, candidates: list, binding_state=None) -> None:
        if node not in self._node:
            self._node_validation_callback(node)
            candidates.append(node)
            if binding_state is not None:
                self._prepare_node_binding(node, binding_state)

    def _validate_nodes_from(self, nodes: Iterable, candidates: list, binding_state):
        for item in nodes:
            node = item
            try:
                is_new = node not in self._node
            except TypeError:
                node, node_data = item
                if not isinstance(node_data, dict):
                    raise
                is_new = node not in self._node
            if is_new:
                self._node_validation_callback(node)
                candidates.append(node)
                self._prepare_node_binding(node, binding_state)
            yield item

    def _edge_count(self, source, destination) -> int:
        try:
            edge_data = self._succ[source][destination]
        except (KeyError, TypeError):
            return 0
        if self.is_multigraph():
            return len(edge_data)
        return 1

    def _predecessor_edge_count(self, source, destination) -> int:
        try:
            edge_data = self._pred[destination][source]
        except (KeyError, TypeError):
            return 0
        if self.is_multigraph():
            return len(edge_data)
        return 1

    def _wire_edge_attr(self, source, destination, key=_MISSING) -> None:
        try:
            edge_data = self._succ[source][destination]
            if self.is_multigraph():
                if key is _MISSING:
                    return
                edge_data = edge_data[key]
        except (KeyError, TypeError):
            return
        if isinstance(edge_data, _ObservableDict):
            edge_data.set_mutation_callback(self._graph_mutated)

    def _wire_edge_pairs(self, edge_states: Iterable) -> None:
        if self.is_multigraph():
            return
        seen = set()
        for source, destination, _ in edge_states:
            pair = source, destination
            if pair not in seen:
                seen.add(pair)
                self._wire_edge_attr(source, destination)

    def _edge_attr_state(self, source, destination, key=_MISSING):
        try:
            data = self._succ[source][destination]
            if self.is_multigraph():
                if key is _MISSING or key is None:
                    return None
                data = data[key]
        except (KeyError, TypeError):
            return None
        return source, destination, key, data, dict(data)

    def _validate_edges_from(
        self, edges: Iterable, candidates: list, edge_states: list, edge_attr_states: list, binding_state
    ):
        for edge in edges:
            try:
                source, destination = edge[0], edge[1]
            except (IndexError, TypeError):
                yield edge
                continue
            self._validate_node_insertion(source, candidates, binding_state)
            self._validate_node_insertion(destination, candidates, binding_state)
            edge_states.append((source, destination, self._edge_count(source, destination)))
            if self.is_multigraph():
                key = _MISSING
                if len(edge) == 4 or (len(edge) == 3 and not hasattr(edge[2], "keys")):
                    key = edge[2]
            else:
                key = _MISSING
            state = self._edge_attr_state(source, destination, key)
            if state is not None and all(existing[3] is not state[3] for existing in edge_attr_states):
                edge_attr_states.append(state)
            yield edge

    def _track_removed_nodes(self, nodes: Iterable, candidates: list, edge_attr_states: list):
        for node in nodes:
            try:
                if node in self._node:
                    candidates.append(node)
                    self._capture_incident_edge_attrs(node, edge_attr_states)
            except TypeError:
                pass
            yield node

    def _track_removed_edges(self, edges: Iterable, edge_states: list, edge_attr_states: list):
        for edge in edges:
            try:
                source, destination = edge[0], edge[1]
            except (IndexError, TypeError):
                yield edge
                continue
            edge_states.append((source, destination, self._edge_count(source, destination)))
            key = edge[2] if self.is_multigraph() and len(edge) >= 3 else _MISSING
            self._capture_removable_edge_attr(source, destination, key, edge_attr_states)
            yield edge

    def _capture_removable_edge_attr(self, source, destination, key, edge_attr_states: list) -> None:
        if self.is_multigraph() and (key is _MISSING or key is None):
            try:
                edge_keys = self._succ[source][destination]
                key = next(reversed(edge_keys))
            except (KeyError, StopIteration, TypeError):
                return
        state = self._edge_attr_state(source, destination, key)
        if state is not None and all(existing[3] is not state[3] for existing in edge_attr_states):
            edge_attr_states.append(state)

    def _capture_incident_edge_attrs(self, node, edge_attr_states: list) -> None:
        if self.is_multigraph():
            edges = itertools.chain(self.out_edges(node, keys=True), self.in_edges(node, keys=True))
            for source, destination, key in edges:
                self._capture_removable_edge_attr(source, destination, key, edge_attr_states)
        else:
            edges = itertools.chain(self.out_edges(node), self.in_edges(node))
            for source, destination in edges:
                self._capture_removable_edge_attr(source, destination, _MISSING, edge_attr_states)

    def _all_edge_attr_states(self) -> list:
        states = []
        if self.is_multigraph():
            for source, destination, key, _ in self.edges(keys=True, data=True):
                self._capture_removable_edge_attr(source, destination, key, states)
        else:
            for source, destination in self.edges:
                self._capture_removable_edge_attr(source, destination, _MISSING, states)
        return states

    def _edge_attr_is_installed(self, source, destination, key, data) -> bool:
        for adjacency, first, second in ((self._succ, source, destination), (self._pred, destination, source)):
            try:
                installed = adjacency[first][second]
                if self.is_multigraph():
                    installed = installed[key]
            except (KeyError, TypeError):
                continue
            if installed is data:
                return True
        return False

    def _detach_removed_edge_attrs(self, edge_attr_states: Iterable) -> None:
        for source, destination, key, data, _ in edge_attr_states:
            if not self._edge_attr_is_installed(source, destination, key, data):
                data._mutation_callback = _MutationCallback(None)

    def _prepare_node_binding(self, node, binding_state) -> None:
        bindings, prepared = binding_state
        if node in prepared:
            return
        prepared.add(node)
        rollback = self._node_insertion_callback(node)
        if callable(rollback):
            bindings.append((node, rollback))

    def _prepare_node_bindings(self, candidates: Iterable, binding_state) -> None:
        for node in candidates:
            self._prepare_node_binding(node, binding_state)

    def _restore_uninstalled_node_bindings(self, bindings: Iterable) -> None:
        for node, rollback in reversed(tuple(bindings)):
            if node not in self._node:
                rollback()

    def _run_node_insertion(self, mutation: Callable[[], Any], candidates: list, binding_state):
        try:
            self._prepare_node_bindings(candidates, binding_state)
            return mutation()
        finally:
            self._restore_uninstalled_node_bindings(binding_state[0])

    @property
    def has_mutation_callback(self) -> bool:
        return self._mutation_callback.alive

    def _graph_mutated(self) -> None:
        self._mutation_serial += 1
        if self._mutation_depth:
            self._mutation_pending = True
        else:
            self._mutation_callback()

    @contextmanager
    def _coalesce_mutations(self):
        self._mutation_depth += 1
        try:
            yield
        finally:
            self._mutation_depth -= 1
            if self._mutation_depth == 0 and self._mutation_pending:
                self._mutation_pending = False
                self._mutation_callback()

    def _run_topology_mutation(self, mutation: Callable[[], Any], changed: Callable[[], bool]):
        pending_before = self._mutation_pending
        failed = False
        with self._coalesce_mutations():
            try:
                return mutation()
            except BaseException:
                failed = True
                raise
            finally:
                serial_before_comparison = self._mutation_serial
                if changed():
                    self._graph_mutated()
                elif not failed and self._mutation_serial == serial_before_comparison:
                    self._mutation_pending = pending_before

    def _edge_attrs_changed(self, edge_attr_states: Iterable) -> bool:
        for source, destination, key, old_data, old_contents in edge_attr_states:
            current_state = self._edge_attr_state(source, destination, key)
            if current_state is None or current_state[3] is not old_data:
                return True
            try:
                if old_contents != dict(old_data):
                    return True
            except Exception:  # pylint:disable=broad-except
                return True
        return False

    def _topology_was_added(self, candidates: Iterable, edge_states: Iterable, edge_attr_states: Iterable = ()) -> bool:
        self._wire_edge_pairs(edge_states)
        return (
            any(node in self._node for node in candidates)
            or any(self._edge_count(source, destination) != old_count for source, destination, old_count in edge_states)
            or self._edge_attrs_changed(edge_attr_states)
        )

    def _topology_was_removed(
        self, candidates: Iterable, edge_states: Iterable, predecessor_edge_states: Iterable = ()
    ) -> bool:
        return (
            any(node not in self._node for node in candidates)
            or any(self._edge_count(source, destination) != old_count for source, destination, old_count in edge_states)
            or any(
                self._predecessor_edge_count(source, destination) != old_count
                for source, destination, old_count in predecessor_edge_states
            )
        )

    def add_node(self, node_for_adding, **attr):
        candidates = []
        binding_state = [], set()
        self._validate_node_insertion(node_for_adding, candidates)
        return self._run_topology_mutation(
            lambda: self._run_node_insertion(
                lambda: super(_ObservableGraphMixin, self).add_node(node_for_adding, **attr), candidates, binding_state
            ),
            lambda: self._topology_was_added(candidates, ()),
        )

    def add_nodes_from(self, nodes_for_adding: Iterable, **attr):
        candidates = []
        binding_state = [], set()
        return self._run_topology_mutation(
            lambda: self._run_node_insertion(
                lambda: super(_ObservableGraphMixin, self).add_nodes_from(
                    self._validate_nodes_from(nodes_for_adding, candidates, binding_state), **attr
                ),
                candidates,
                binding_state,
            ),
            lambda: self._topology_was_added(candidates, ()),
        )

    def remove_node(self, n):
        candidates = [n] if n in self._node else []
        edge_attr_states = []
        if candidates:
            self._capture_incident_edge_attrs(n, edge_attr_states)
        try:
            return self._run_topology_mutation(
                lambda: super(_ObservableGraphMixin, self).remove_node(n),
                lambda: self._topology_was_removed(candidates, ()),
            )
        finally:
            self._detach_removed_edge_attrs(edge_attr_states)

    def remove_nodes_from(self, nodes: Iterable):
        candidates = []
        edge_attr_states = []
        try:
            return self._run_topology_mutation(
                lambda: super(_ObservableGraphMixin, self).remove_nodes_from(
                    self._track_removed_nodes(nodes, candidates, edge_attr_states)
                ),
                lambda: self._topology_was_removed(candidates, ()),
            )
        finally:
            self._detach_removed_edge_attrs(edge_attr_states)

    def add_edge(self, u_of_edge, v_of_edge, *args, **attr):
        candidates = []
        binding_state = [], set()
        self._validate_node_insertion(u_of_edge, candidates)
        self._validate_node_insertion(v_of_edge, candidates)
        edge_states = [(u_of_edge, v_of_edge, self._edge_count(u_of_edge, v_of_edge))]
        key = args[0] if args else attr.get("key", _MISSING) if self.is_multigraph() else _MISSING
        edge_attr_state = self._edge_attr_state(u_of_edge, v_of_edge, key)
        edge_attr_states = () if edge_attr_state is None else (edge_attr_state,)

        def add_edge():
            key = super(_ObservableGraphMixin, self).add_edge(u_of_edge, v_of_edge, *args, **attr)
            self._wire_edge_attr(u_of_edge, v_of_edge, key if self.is_multigraph() else _MISSING)
            return key

        return self._run_topology_mutation(
            lambda: self._run_node_insertion(add_edge, candidates, binding_state),
            lambda: self._topology_was_added(candidates, edge_states, edge_attr_states),
        )

    def add_edges_from(self, ebunch_to_add: Iterable, **attr):
        candidates = []
        binding_state = [], set()
        edge_states = []
        edge_attr_states = []
        return self._run_topology_mutation(
            lambda: self._run_node_insertion(
                lambda: super(_ObservableGraphMixin, self).add_edges_from(
                    self._validate_edges_from(ebunch_to_add, candidates, edge_states, edge_attr_states, binding_state),
                    **attr,
                ),
                candidates,
                binding_state,
            ),
            lambda: self._topology_was_added(candidates, edge_states, edge_attr_states),
        )

    def add_weighted_edges_from(self, ebunch_to_add: Iterable, weight="weight", **attr):
        candidates = []
        binding_state = [], set()
        edge_states = []
        edge_attr_states = []
        return self._run_topology_mutation(
            lambda: self._run_node_insertion(
                lambda: super(_ObservableGraphMixin, self).add_weighted_edges_from(
                    self._validate_edges_from(ebunch_to_add, candidates, edge_states, edge_attr_states, binding_state),
                    weight=weight,
                    **attr,
                ),
                candidates,
                binding_state,
            ),
            lambda: self._topology_was_added(candidates, edge_states, edge_attr_states),
        )

    def remove_edge(self, u, v, *args, **kwargs):
        edge_states = [(u, v, self._edge_count(u, v))]
        edge_attr_states = []
        key = args[0] if args else kwargs.get("key", _MISSING)
        self._capture_removable_edge_attr(u, v, key, edge_attr_states)
        try:
            return self._run_topology_mutation(
                lambda: super(_ObservableGraphMixin, self).remove_edge(u, v, *args, **kwargs),
                lambda: self._topology_was_removed((), edge_states),
            )
        finally:
            self._detach_removed_edge_attrs(edge_attr_states)

    def remove_edges_from(self, ebunch: Iterable):
        edge_states = []
        edge_attr_states = []
        try:
            return self._run_topology_mutation(
                lambda: super(_ObservableGraphMixin, self).remove_edges_from(
                    self._track_removed_edges(ebunch, edge_states, edge_attr_states)
                ),
                lambda: self._topology_was_removed((), edge_states),
            )
        finally:
            self._detach_removed_edge_attrs(edge_attr_states)

    def update(self, edges=None, nodes=None):
        with self._coalesce_mutations():
            return super().update(edges=edges, nodes=nodes)

    def clear(self):
        candidates = list(self._node)
        edge_attr_data = self._all_edge_attr_states()
        edge_states = [
            (source, destination, self._edge_count(source, destination))
            for source, destinations in self._succ.items()
            for destination in destinations
        ]
        predecessor_edge_states = [
            (source, destination, self._predecessor_edge_count(source, destination))
            for destination, sources in self._pred.items()
            for source in sources
        ]
        try:
            return self._run_topology_mutation(
                super().clear,
                lambda: self._topology_was_removed(candidates, edge_states, predecessor_edge_states),
            )
        finally:
            self._detach_removed_edge_attrs(edge_attr_data)

    def clear_edges(self):
        edge_attr_data = self._all_edge_attr_states()
        edge_states = [
            (source, destination, self._edge_count(source, destination))
            for source, destinations in self._succ.items()
            for destination in destinations
        ]
        predecessor_edge_states = [
            (source, destination, self._predecessor_edge_count(source, destination))
            for destination, sources in self._pred.items()
            for source in sources
        ]
        try:
            return self._run_topology_mutation(
                super().clear_edges,
                lambda: self._topology_was_removed((), edge_states, predecessor_edge_states),
            )
        finally:
            self._detach_removed_edge_attrs(edge_attr_data)

    def __getstate__(self):
        state = self.__dict__.copy()
        state["_mutation_callback"] = _MutationCallback(None)
        state["_node_validation_callback"] = _MutationCallback(None)
        state["_node_insertion_callback"] = _MutationCallback(None)
        state["_mutation_depth"] = 0
        state["_mutation_pending"] = False
        state["_mutation_serial"] = 0
        return state

    def __setstate__(self, state: Mapping[str, Any]) -> None:
        self.__dict__.update(state)
        self._mutation_callback = _MutationCallback(None)
        self._node_validation_callback = _MutationCallback(None)
        self._node_insertion_callback = _MutationCallback(None)
        self._mutation_depth = 0
        self._mutation_pending = False
        self._mutation_serial = 0
        self.set_mutation_callback(None)


class ObservableDiGraph(_ObservableGraphMixin, networkx.DiGraph):
    pass


class ObservableMultiDiGraph(_ObservableGraphMixin, networkx.MultiDiGraph):
    pass
