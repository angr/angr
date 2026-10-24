# pylint:disable=protected-access
"""
Scan-time functions for CFGFast.

CFGFast's scan builds functions that make_functions() throws away; only their flags, returning status, info keys,
transition graphs and the callgraph are read back. RecoveryFunctionManager keeps that state in a Rust
RecoveryFunctions store with an int-only ``_add_*`` API (no CodeNode objects per edge) and hands out
RecoveryFunction views over the records. It is installed as kb.functions for the duration of the scan only; the
FunctionManager that make_functions() builds afterwards is a normal one.
"""

from __future__ import annotations

from collections.abc import Generator, Iterable, Iterator
from typing import TYPE_CHECKING

import networkx

from angr.codenode import CodeNode
from angr.errors import SimEngineError
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin
from angr.rustylib.function_graph import NodeKind
from angr.rustylib.recovery_functions import (
    CG_CALL,
    CG_EXCEPTION,
    CG_FAKERET,
    CG_TRANSITION,
    LOG_ADD_EDGE,
    LOG_GRAPH_NODE,
    LOG_REGISTER,
    LOG_REMOVE_EDGE,
    LOG_SET_CONFIRMED,
    REG_IN_GRAPH,
    REG_NEW_LOCAL,
    RecoveryFunctions,
)

from .function import Function, FunctionInfo, PrototypeSource, _node_key
from .function_manager import FunctionManager, _missing

if TYPE_CHECKING:
    from angr import KnowledgeBase

    from .transition_graph import TransitionGraph

NodeSpec = tuple[NodeKind, int, int, bool]

_CG_TYPE_NAMES = {CG_CALL: "call", CG_FAKERET: "fakeret", CG_TRANSITION: "transition", CG_EXCEPTION: "exception"}
_CG_TYPE_IDS = {v: k for k, v in _CG_TYPE_NAMES.items()}


def node_spec(node: CodeNode) -> NodeSpec:
    """The (kind, addr, size, thumb) identity of a CodeNode."""
    return _node_key(node)


class RecoveryFunctionInfo(FunctionInfo):
    """
    ``Function.info`` of a RecoveryFunction: a dict interface over the record's info map.
    """

    def __init__(self, func: RecoveryFunction):  # pylint:disable=super-init-not-called
        self._func = func

    @property
    def data(self) -> dict:  # type: ignore[override]
        return self._func._store.info_dict(self._func.addr)

    @data.setter
    def data(self, d: dict) -> None:
        self._func._store.info_replace(self._func.addr, dict(d))

    def __getitem__(self, key):
        v = self._func._store.info_get(self._func.addr, key)
        if v is None and not self._func._store.info_contains(self._func.addr, key):
            raise KeyError(key)
        return v

    def __setitem__(self, key, value):
        if not isinstance(value, (str, int, float, bool, list, dict)):
            raise TypeError(
                "FunctionInfo only supports JSON-serializable values (str, int, float, bool, list, and dict)."
            )
        if not isinstance(key, str):
            raise TypeError("FunctionInfo only supports str keys.")
        self._func._store.info_set(self._func.addr, key, value)

    def __delitem__(self, key):
        if not self._func._store.info_del(self._func.addr, key):
            raise KeyError(key)

    def __contains__(self, key):
        return isinstance(key, str) and self._func._store.info_contains(self._func.addr, key)

    def __iter__(self):
        return iter(self._func._store.info_keys(self._func.addr))

    def __len__(self):
        return self._func._store.info_len(self._func.addr)

    def get(self, key, default=None):
        if key in self:
            return self[key]
        return default

    def copy(self, owner: Function) -> FunctionInfo:  # type: ignore[override]
        new_info = FunctionInfo(owner)
        new_info.data = self.data
        return new_info

    def __repr__(self):
        return repr(self.data)


class RecoveryFunction(Function):
    """
    A Function whose flags, name, returning status, info and transition graph live in a RecoveryFunctions store.
    Before every read, the transition_graph mirror and the block-address cache are brought up to date from the
    store's mutation log (as Function updates them on each mutation), and the local view is dropped (as Function
    drops it on each mutation).
    """

    __slots__ = ("_gen", "_store")

    def __init__(self, function_manager: RecoveryFunctionManager, addr: int, syscall: bool | None = None):
        store = function_manager._store
        graph = store.create(addr)
        self._store = store
        self._gen = 0
        self._init_slots(function_manager, addr, graph, None, None, None, PrototypeSource.NONE, False)
        project = self.project
        assert project is not None
        is_syscall = project.simos.is_syscall_addr(addr) if syscall is None else syscall
        store.set_is_syscall(addr, is_syscall)
        store.set_is_simprocedure(addr, is_syscall or project.is_hooked(addr))
        store.set_is_plt(addr, function_manager.is_plt_cached(addr))
        store.set_name(addr, self._get_initial_name())
        store.set_binary_name(addr, self._get_initial_binary_name())
        store.set_returning(addr, self._get_initial_returning())
        self._init_prototype_and_calling_convention()

    @classmethod
    def _adopt(cls, function_manager: RecoveryFunctionManager, func: Function) -> RecoveryFunction:
        """
        Make a view over an existing Function. The graph is shared with it.
        """
        self = cls.__new__(cls)
        store = function_manager._store
        store.import_record(
            func.addr,
            func._graph,
            func.name,
            func.is_default_name,
            list(func.previous_names),
            func.binary_name,
            func.is_syscall,
            func.is_simprocedure,
            func.is_plt,
            func.is_alignment,
            func.returning,
            dict(func._info_data()),
        )
        self._store = store
        self._gen = 0
        self._init_slots(
            function_manager,
            func.addr,
            func._graph,
            func.calling_convention,
            None,
            func.prototype_libname,
            PrototypeSource.NONE,
            False,
        )
        self._copy_prototypes_from(func)
        self._from_signature = func.from_signature
        self.normalized = func.normalized
        self.ran_cca = func.ran_cca
        self.tags = func.tags
        self.bp_on_stack = func.bp_on_stack
        self.retaddr_on_stack = func.retaddr_on_stack
        self.sp_delta = func.sp_delta
        return self

    #
    # Record fields
    #

    @property
    def name(self):
        return self._store.name(self.addr)

    @name.setter
    def name(self, v):
        old = self._store.name(self.addr)
        if v == old:
            return
        self._store.add_previous_name(self.addr, old)
        if self._function_manager is not None:
            self._function_manager.function_name_changed(self.addr, old, v)
            self._function_manager._kb.labels[self.addr] = v
        self._store.set_name(self.addr, v)
        self.mark_dirty()

    @property
    def is_default_name(self) -> bool:  # type: ignore[override]
        return self._store.is_default_name(self.addr)

    @is_default_name.setter
    def is_default_name(self, v: bool) -> None:
        self._store.set_is_default_name(self.addr, v)

    @property
    def previous_names(self) -> list[str]:  # type: ignore[override]
        return self._store.previous_names(self.addr)

    @previous_names.setter
    def previous_names(self, v: list[str]) -> None:
        self._store.set_previous_names(self.addr, list(v))

    @property
    def binary_name(self) -> str | None:  # type: ignore[override]
        return self._store.binary_name(self.addr)

    @binary_name.setter
    def binary_name(self, v: str | None) -> None:
        self._store.set_binary_name(self.addr, v)

    @property
    def returning(self):
        return self._store.returning(self.addr)

    @returning.setter
    def returning(self, v):
        if self._store.returning(self.addr) == v:
            return
        self._store.set_returning(self.addr, v)
        self.mark_dirty()

    @property
    def is_plt(self) -> bool:
        return self._store.is_plt(self.addr)

    @is_plt.setter
    def is_plt(self, v: bool):
        self._store.set_is_plt(self.addr, v)

    @property
    def is_simprocedure(self) -> bool:
        return self._store.is_simprocedure(self.addr)

    @is_simprocedure.setter
    def is_simprocedure(self, v: bool):
        self._store.set_is_simprocedure(self.addr, v)

    @property
    def is_syscall(self) -> bool:
        return self._store.is_syscall(self.addr)

    @is_syscall.setter
    def is_syscall(self, v: bool):
        self._store.set_is_syscall(self.addr, v)

    @property
    def is_alignment(self) -> bool:
        return self._store.is_alignment(self.addr)

    @is_alignment.setter
    def is_alignment(self, v: bool):
        self._store.set_is_alignment(self.addr, v)

    @property
    def info(self) -> FunctionInfo:
        if not isinstance(self._info, RecoveryFunctionInfo):
            self._info = RecoveryFunctionInfo(self)
        return self._info

    def _info_data(self) -> dict:
        return self._store.info_dict(self.addr)

    @info.setter
    def info(self, info: FunctionInfo | dict):
        self._store.info_replace(self.addr, dict(info))
        self._dirty = True
        if self._function_manager is not None:
            self._function_manager.index_key_func_addrs(self)

    #
    # Graph caches: synchronized from the store's mutation log
    #

    def _sync(self) -> None:
        gen = self._store.generation(self.addr)
        if gen == self._gen:
            return
        self._gen = gen
        # Function rebuilds the local view after every mutation; its node order depends on that
        self._local_transition_graph = None
        tg = self._transition_graph
        bac = self._block_addrs_cache
        if tg is None and bac is None:
            return
        log = self._store.take_log(self.addr)
        if not log:
            return
        g = self._graph
        objs = self._node_obj
        for op, a, b in log:
            if op == LOG_REGISTER:
                if b & REG_NEW_LOCAL and bac is not None:
                    bac.add(g.node_addr(a))
                if tg is not None and b & REG_IN_GRAPH:
                    tg._mirror_add_node(objs(a))
            elif tg is None:
                continue
            elif op == LOG_GRAPH_NODE:
                tg._mirror_add_node(objs(a))
            elif op == LOG_ADD_EDGE:
                data = g.edge_data(a, b)
                if data is None:
                    tg._mirror_add_node(objs(a))
                    tg._mirror_add_node(objs(b))
                else:
                    tg._mirror_add_edge(objs(a), objs(b), data)
            elif op == LOG_SET_CONFIRMED:
                confirmed = g.edge_confirmed(a, b)
                src, dst = objs(a), objs(b)
                if confirmed is not None and tg.has_edge(src, dst):
                    tg._mirror_set_edge_attr(src, dst, "confirmed", confirmed)
            elif op == LOG_REMOVE_EDGE:
                tg._mirror_remove_edge(objs(a), objs(b))

    def _enable_log(self) -> None:
        self._store.enable_log(self.addr)

    @property
    def transition_graph(self) -> TransitionGraph:
        self._sync()
        if self._transition_graph is None:
            self._enable_log()
        return super().transition_graph

    @property
    def graph(self) -> TransitionGraph:
        self._sync()
        return super().graph

    @property
    def block_addrs_set(self):
        self._sync()
        if self._block_addrs_cache is None:
            self._enable_log()
        return super().block_addrs_set

    def transition_out_edges(self, node: CodeNode):
        self._sync()
        return super().transition_out_edges(node)

    def transition_in_edges(self, node: CodeNode):
        self._sync()
        return super().transition_in_edges(node)

    # Python-side mutators keep working on the shared graph; they touch the mirrors themselves after a sync.

    def register(self, is_local: bool, node: CodeNode, update_func_block_count: bool = True) -> int:
        self._sync()
        return super().register(is_local, node, update_func_block_count=update_func_block_count)

    def _graph_node(self, node: CodeNode) -> int:
        self._sync()
        return super()._graph_node(node)

    def _add_edge(self, src: int, dst: int, kind, present: int, **data) -> None:
        self._sync()
        super()._add_edge(src, dst, kind, present, **data)

    def _set_edge_confirmed(self, src: int, dst: int, confirmed: bool) -> None:
        self._sync()
        super()._set_edge_confirmed(src, dst, confirmed)

    def remove_edge(self, from_node: CodeNode, to_node: CodeNode) -> None:
        self._sync()
        super().remove_edge(from_node, to_node)

    def remove_graph_node(self, node: CodeNode) -> None:
        self._sync()
        super().remove_graph_node(node)

    def clear_transition_graph(self):
        self._graph = self._store.reset_graph(self.addr)
        self._gen = self._store.generation(self.addr)
        self._transition_graph = None
        self._node_objs = None
        self._block_addrs_cache = None
        self._local_transition_graph = None
        self._dirty = True

    def normalize(self):
        self._sync()
        super().normalize()
        self._store.disable_log(self.addr)
        self._gen = self._store.generation(self.addr)

    def update_func_block_count(self) -> None:
        pass

    def __repr__(self):
        return f"<RecoveryFunction {self.name} ({self.addr:#x})>"

    def __reduce__(self):
        raise TypeError("RecoveryFunction views cannot be pickled; they only exist during CFG recovery")


class RecoveryCallGraph:
    """
    The subset of the networkx.MultiDiGraph interface that CFG recovery uses, over the store's callgraph.
    """

    __slots__ = ("_store",)

    def __init__(self, store: RecoveryFunctions):
        self._store = store

    def __contains__(self, n) -> bool:
        return isinstance(n, int) and self._store.cg_contains(n)

    def __len__(self) -> int:
        return self._store.cg_number_of_nodes()

    def __iter__(self) -> Iterator[int]:
        return iter(self._store.cg_nodes())

    def __getitem__(self, u: int) -> dict[int, dict[int, dict[str, str]]]:
        if not self._store.cg_contains(u):
            raise KeyError(u)
        out: dict[int, dict[int, dict[str, str]]] = {}
        for _, v, ty in self._store.cg_out_edges(u):
            keyed = out.setdefault(v, {})
            keyed[len(keyed)] = {"type": _CG_TYPE_NAMES[ty]}
        return out

    def nodes(self) -> list[int]:
        return self._store.cg_nodes()

    def number_of_nodes(self) -> int:
        return self._store.cg_number_of_nodes()

    def number_of_edges(self) -> int:
        return self._store.cg_number_of_edges()

    def add_node(self, n: int) -> None:
        self._store.cg_add_node(n)

    def add_edge(self, u: int, v: int, type: str = "call") -> None:  # pylint:disable=redefined-builtin
        self._store.cg_add_edge(u, v, _CG_TYPE_IDS[type])

    def remove_node(self, n: int) -> None:
        if not self._store.cg_remove_node(n):
            raise networkx.NetworkXError(f"The node {n} is not in the graph.")

    def has_edge(self, u: int, v: int) -> bool:
        return self._store.cg_has_edge(u, v)

    def predecessors(self, n: int) -> Iterator[int]:
        try:
            return iter(self._store.cg_predecessors(n))
        except KeyError as err:
            raise networkx.NetworkXError(f"The node {n} is not in the digraph.") from err

    def successors(self, n: int) -> Iterator[int]:
        try:
            return iter(self._store.cg_successors(n))
        except KeyError as err:
            raise networkx.NetworkXError(f"The node {n} is not in the digraph.") from err

    def _edge_list(self, raw: list[tuple[int, int, int]], data: bool) -> list:
        if data:
            return [(u, v, {"type": _CG_TYPE_NAMES[ty]}) for u, v, ty in raw]
        return [(u, v) for u, v, _ in raw]

    def out_edges(self, nbunch: int | None = None, data: bool = False) -> list:
        return self._edge_list(self._store.cg_out_edges(nbunch), data)

    def in_edges(self, nbunch: int, data: bool = False) -> list:
        return self._edge_list(self._store.cg_in_edges(nbunch), data)

    def edges(self, data: bool = False) -> list:
        return self._edge_list(self._store.cg_out_edges(None), data)

    @property
    def in_degree(self) -> _CallGraphDegree:
        return _CallGraphDegree(self._store.cg_in_degree)

    @property
    def out_degree(self) -> _CallGraphDegree:
        return _CallGraphDegree(self._store.cg_out_degree)

    def copy(self) -> networkx.MultiDiGraph:
        return self.to_networkx()

    def to_networkx(self) -> networkx.MultiDiGraph:
        g: networkx.MultiDiGraph = networkx.MultiDiGraph()
        g.add_nodes_from(self._store.cg_nodes())
        for u, v, ty in self._store.cg_out_edges(None):
            g.add_edge(u, v, type=_CG_TYPE_NAMES[ty])
        return g


class _CallGraphDegree:
    __slots__ = ("_f",)

    def __init__(self, f):
        self._f = f

    def __getitem__(self, n: int) -> int:
        return self._f(n)

    def __call__(self, n: int) -> int:
        return self._f(n)


class RecoveryFunctionMap:
    """
    The ``_function_map`` of a RecoveryFunctionManager: the FunctionDict interface that CFG recovery code uses.
    """

    __slots__ = ("_manager",)

    def __init__(self, manager: RecoveryFunctionManager):
        self._manager = manager

    def __contains__(self, addr) -> bool:
        return isinstance(addr, int) and self._manager._store.contains(addr)

    def __len__(self) -> int:
        return len(self._manager._store)

    def __iter__(self) -> Iterator[int]:
        return iter(self._manager._store.addrs())

    def __getitem__(self, addr: int) -> RecoveryFunction:
        if not isinstance(addr, int):
            raise TypeError(f"RecoveryFunctionMap only supports int as key type, not {type(addr)}")
        return self._manager._get_or_create(addr)

    def get(self, addr, default=_missing, /, meta_only: bool = False):  # pylint:disable=unused-argument
        func = self._manager._view(addr)
        if func is not None:
            return func
        if default is _missing:
            raise KeyError(addr)
        return default

    def keys(self) -> list[int]:
        return self._manager._store.addrs()

    def values(self) -> Generator[RecoveryFunction]:
        for addr in self._manager._store.addrs():
            yield self._manager._get_or_create(addr)

    def items(self) -> Generator[tuple[int, RecoveryFunction]]:
        for addr in self._manager._store.addrs():
            yield addr, self._manager._get_or_create(addr)

    def irange(self, minimum=None, maximum=None, inclusive=(True, True), reverse=False) -> Iterator[int]:
        return iter(self._manager._store.addrs_in_range(minimum, maximum, tuple(inclusive), reverse))

    def floor_addr(self, addr: int) -> int:
        r = self._manager._store.floor_addr(addr)
        if r is None:
            raise KeyError(addr)
        return r

    def ceiling_addr(self, addr: int) -> int:
        r = self._manager._store.ceiling_addr(addr)
        if r is None:
            raise KeyError(addr)
        return r


class RecoveryFunctionManager(FunctionManager[int]):
    """
    The kb.functions of a CFGFast scan. Function state lives in a Rust RecoveryFunctions store; RecoveryFunction
    views are created on demand and cached for the lifetime of the manager.
    """

    def __init__(self, kb: KnowledgeBase, existing: FunctionManager | None = None):
        KnowledgeBasePlugin.__init__(self, kb=kb)
        self.function_address_types = kb._project.arch.function_address_types
        self.address_types = kb._project.arch.address_types
        self._store = RecoveryFunctions()
        self._store.set_factory(self._store_factory)
        self._views: dict[int, RecoveryFunction] = {}
        self._function_map = RecoveryFunctionMap(self)  # type: ignore[assignment]
        self._callgraph = RecoveryCallGraph(self._store)
        self._arg_registers = kb._project.arch.argument_registers
        self._init_caches()
        if existing is not None:
            self._import(existing)

    @property
    def store(self) -> RecoveryFunctions:
        return self._store

    @property
    def callgraph(self) -> RecoveryCallGraph:  # type: ignore[override]
        return self._callgraph

    @callgraph.setter
    def callgraph(self, v) -> None:
        raise AttributeError("the callgraph of a RecoveryFunctionManager lives in its store")

    def _import(self, existing: FunctionManager) -> None:
        if isinstance(existing, RecoveryFunctionManager):
            existing_views = existing._views
            funcs: Iterable[Function] = (existing_views.get(addr) or existing._get_or_create(addr) for addr in existing)
        else:
            funcs = existing.values()
        for func in funcs:
            view = RecoveryFunction._adopt(self, func)
            self._views[func.addr] = view
            self._function_added(view)
        for func_type, addrs in existing.get_key_func_type_and_addrs().items():
            for addr in addrs:
                self.add_key_func_addr(func_type, addr)
        for u, v, data in existing.callgraph.edges(data=True):
            if self._store.contains(u) and self._store.contains(v):
                self._store.cg_add_edge(u, v, _CG_TYPE_IDS[data.get("type", "call")])

    def to_function_manager(self) -> FunctionManager:
        """
        A plain FunctionManager with Function copies of every view; the graphs are shared.
        """
        fm: FunctionManager = FunctionManager(self._kb)
        addrs = self._store.addrs()
        views = [self._get_or_create(addr) for addr in addrs]
        funcs, infos = Function._bulk_from_store(self._store, addrs)
        for func, view, info in zip(funcs, views, infos):
            func._init_py_slots(fm, view.calling_convention)
            if info:
                func.info.data = info
            func._copy_prototypes_from(view)
            func._prototype_libname = view.prototype_libname
            func._from_signature = view.from_signature
            func.normalized = view.normalized
            func.ran_cca = view.ran_cca
            func.tags = view.tags
        fm._add_new_functions(funcs)
        for u, v, ty in self._store.cg_out_edges(None):
            fm.callgraph.add_edge(u, v, type=_CG_TYPE_NAMES[ty])
        for func_type, addrs in self.get_key_func_type_and_addrs().items():
            for addr in addrs:
                fm.add_key_func_addr(func_type, addr)
        return fm

    #
    # Views
    #

    def _view(self, addr) -> RecoveryFunction | None:
        return self._views.get(addr)

    def _get_or_create(self, addr: int) -> RecoveryFunction:
        view = self._views.get(addr)
        if view is None:
            view = self._create(addr)
        return view

    def _create(self, addr: int, syscall: bool | None = None) -> RecoveryFunction:
        view = RecoveryFunction(self, addr, syscall=syscall)
        self._views[addr] = view
        self._function_added(view)
        return view

    def _store_factory(self, addr: int, syscall: bool) -> None:
        """
        Called by the store's recovery API for a missing function, the way FunctionManager creates one on access.
        """
        func = self._create(addr)
        if syscall:
            func.is_syscall = True

    def _function_added(self, func: Function):
        self._index.set_from_signature(func.addr, func.from_signature)
        self.index_key_func_addrs(func)
        self.function_name_changed(func.addr, None, func.name)

    #
    # Recovery API: node specs, CodeNodes and ints are all accepted
    #

    def _spec(self, node, size=None) -> NodeSpec:
        if type(node) is tuple:  # pylint:disable=unidiomatic-typecheck
            return node
        if isinstance(node, self.address_types):
            node = self._kb._project.factory.snippet(node, size=size)
        return _node_key(node)

    def _add_node(self, function_addr, node, syscall=None, size=None):
        spec = self._spec(node, size=size)
        self._store.add_node(function_addr, spec, syscall)

    def _add_call_to(
        self,
        function_addr,
        from_node,
        to_addr,
        retn_node=None,
        syscall: bool = False,
        stmt_idx=None,
        ins_addr=None,
        return_to_outside: bool = False,
    ):
        from_spec = self._spec(from_node)
        retn_spec = None if retn_node is None else self._spec(retn_node)
        self._store.add_call_to(
            function_addr, from_spec, to_addr, retn_spec, syscall, stmt_idx, ins_addr, return_to_outside
        )

    def _add_fakeret_to(
        self, function_addr, from_node, to_node, confirmed=None, syscall=None, to_outside=False, to_function_addr=None
    ):
        from_spec = self._spec(from_node)
        to_spec = self._spec(to_node)
        self._store.add_fakeret_to(function_addr, from_spec, to_spec, confirmed, syscall, to_outside, to_function_addr)

    def _remove_fakeret(self, function_addr, from_node, to_node):
        from_spec = self._spec(from_node)
        to_spec = self._spec(to_node)
        if not self._store.remove_fakeret(function_addr, from_spec, to_spec):
            raise networkx.NetworkXError(f"The edge {from_node}-{to_node} is not in the graph.")

    def _add_return_from(self, function_addr, from_node, to_node=None):  # pylint:disable=unused-argument
        from_spec = self._spec(from_node)
        self._store.add_return_from(function_addr, from_spec)

    def _add_transition_to(self, function_addr, from_node, to_node, ins_addr=None, stmt_idx=None, is_exception=False):
        from_spec = self._spec(from_node)
        to_spec = self._spec(to_node)
        self._store.add_transition_to(function_addr, from_spec, to_spec, ins_addr, stmt_idx, is_exception)

    def _add_outside_transition_to(
        self, function_addr, from_node, to_node, to_function_addr=None, ins_addr=None, stmt_idx=None, is_exception=False
    ):
        from_spec = self._spec(from_node)
        try:
            to_spec = self._spec(to_node)
        except SimEngineError:
            # the target cannot be lifted; only record the jump-out site
            to_spec = None
        self._store.add_outside_transition_to(
            function_addr, from_spec, to_spec, to_function_addr, ins_addr, stmt_idx, is_exception
        )

    def _add_return_from_call(self, function_addr, src_function_addr, to_node, to_outside=False):
        to_spec = self._spec(to_node)
        self._store.add_return_from_call(function_addr, src_function_addr, to_spec, to_outside)

    #
    # Dict methods
    #

    def __contains__(self, item):
        if type(item) is int:  # pylint:disable=unidiomatic-typecheck
            return self._store.contains(item)
        try:
            _ = self[item]
            return True
        except (KeyError, TypeError):
            return False

    def __setitem__(self, k, v):
        if not isinstance(k, int):
            raise TypeError("FunctionManager.__setitem__ keys must be an int")
        if not isinstance(v, Function):
            raise TypeError("FunctionManager.__setitem__ values must be Functions")
        if self._store.contains(k):
            del self[k]
        view = v if isinstance(v, RecoveryFunction) and v._store is self._store else RecoveryFunction._adopt(self, v)
        self._views[k] = view
        self._function_added(view)

    def __delitem__(self, k):
        if not isinstance(k, int):
            raise TypeError("FunctionManager.__delitem__ only accepts int addresses")
        view = self._views.pop(k, None)
        previous_names = view.previous_names if view is not None else []
        self._store.remove(k)
        self._index.function_removed(k, previous_names)

    def __len__(self):
        return len(self._store)

    def __iter__(self):
        yield from self._store.addrs()

    def items(self, /, meta_only: bool = False) -> Generator[tuple[int, Function]]:  # type: ignore
        for addr in self._store.addrs():
            yield addr, self._get_or_create(addr)

    def values(self, /, meta_only: bool = False) -> Generator[Function]:  # type: ignore
        for addr in self._store.addrs():
            yield self._get_or_create(addr)

    def get_by_addr(self, addr, meta_only: bool = False) -> Function:
        view = self._views.get(addr)
        if view is None:
            raise KeyError(addr)
        return view

    def contains_addr(self, addr):
        return self._store.contains(addr)

    def ceiling_addr(self, addr: int) -> int | None:
        return self._store.ceiling_addr(addr)

    def ceiling_func(self, addr) -> Function | None:
        next_addr = self._store.ceiling_addr(addr)
        return None if next_addr is None else self._views[next_addr]

    def floor_addr(self, addr: int) -> int | None:
        return self._store.floor_addr(addr)

    def floor_func(self, addr):
        prev_addr = self._store.floor_addr(addr)
        return None if prev_addr is None else self._views[prev_addr]

    def function(
        self,
        addr: int | None = None,
        name: str | None = None,
        check_previous_names: bool = False,
        create: bool = False,
        syscall: bool = False,
        plt: bool | None = None,
    ) -> Function | None:
        if name is not None and name.startswith("sub_"):
            for func in self.get_by_name(name, check_previous_names=check_previous_names):
                if plt is None or func.is_plt == plt:
                    return func
            try:
                addr = int(name.split("_")[-1], 16)
                name = None
            except ValueError:
                pass

        if addr is not None:
            f = self._views.get(addr)
            if f is not None:
                if plt is None or f.is_plt == plt:
                    return f
            elif create:
                f = self._create(addr)
                if name is not None:
                    f.name = name
                if syscall:
                    f.is_syscall = True
                return f
        elif name is not None:
            func = self.query(name, check_previous_names=check_previous_names)
            if func is not None:
                return func
            for func in self.get_by_name(name, check_previous_names=check_previous_names):
                if plt is None or func.is_plt == plt:
                    return func

        return None

    def rebuild_callgraph(self):
        self._store.cg_clear()
        for addr in self._store.addrs():
            func = self._get_or_create(addr)
            if func.block_addrs_set:
                for target in func.outgoing_function_targets():
                    if self._store.contains(target):
                        self._store.cg_add_edge(addr, target, CG_CALL)

    #
    # Caches that live in the store
    #

    def set_function_returning(self, addr: int, v: bool | None) -> None:
        if self._store.contains(addr):
            self._store.set_returning(addr, v)

    def nonreturning_func_addrs(self) -> Generator[int]:
        yield from self._store.nonreturning_addrs()

    def unknown_returning_func_addrs(self) -> Generator[int]:
        yield from self._store.unknown_returning_addrs()

    def is_func_nonreturning(self, addr: int) -> bool:
        return self._store.is_nonreturning(addr)

    def is_func_returning_unknown(self, addr: int) -> bool:
        return self._store.is_returning_unknown(addr)

    def get_func_block_count(self, addr: int) -> int | None:
        return self._store.block_count(addr)

    def set_func_block_count(self, addr: int, count: int) -> None:
        pass

    def get_func_addr_with_block_count(self, block_count: int) -> set[int]:
        return set(self._store.addrs_with_block_count(block_count))

    @property
    def cache_limit(self) -> int | None:
        return None

    @cache_limit.setter
    def cache_limit(self, value: int) -> None:
        pass

    #
    # Unsupported FunctionManager features
    #

    def copy(self):
        return self.to_function_manager()

    def clear(self):
        self._store = RecoveryFunctions()
        self._store.set_factory(self._store_factory)
        self._views = {}
        self._callgraph = RecoveryCallGraph(self._store)
        self._init_caches()

    def __getstate__(self):
        raise TypeError("RecoveryFunctionManager cannot be pickled; it only exists during CFG recovery")

    def __setstate__(self, state):
        raise TypeError("RecoveryFunctionManager cannot be unpickled")


__all__ = (
    "NodeSpec",
    "RecoveryCallGraph",
    "RecoveryFunction",
    "RecoveryFunctionInfo",
    "RecoveryFunctionManager",
    "RecoveryFunctionMap",
    "node_spec",
)
