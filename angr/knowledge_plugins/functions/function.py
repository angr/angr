# pylint:disable=too-many-boolean-expressions
from __future__ import annotations

import contextlib
import itertools
import json
import logging
import os
import re
from collections import UserDict, defaultdict
from collections.abc import Iterable, Iterator
from enum import Enum
from functools import wraps
from typing import TYPE_CHECKING

import networkx
import pydemumble
from archinfo.arch_arm import is_arm_arch
from cle.backends.symbol import Symbol

from angr import claripy
from angr.calling_conventions import DEFAULT_CC, SimCC, default_cc_for_project
from angr.codenode import BlockNode, CodeNode, FuncNode, HookNode, SyscallNode
from angr.errors import AngrValueError, SimEngineError, SimMemoryError
from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort
from angr.knowledge_plugins.xrefs.xref import XRef
from angr.procedures import SIM_LIBRARIES
from angr.procedures.definitions import SimLibrary, SimSyscallLibrary
from angr.protos import function_pb2
from angr.rust.utils.demangler import demangle
from angr.rustylib.function_graph import (
    PRESENT_CONFIRMED,
    PRESENT_INS_ADDR,
    PRESENT_OUTSIDE,
    PRESENT_STMT_IDX,
    PRESENT_TYPE,
    EdgeKind,
    EndpointKind,
    FunctionGraph,
    NodeKind,
    SiteKind,
)
from angr.serializable import Serializable
from angr.sim_type import SimTypeFunction, parse_defns
from angr.utils.library import get_cpp_function_name_and_metadata
from angr.utils.types import dereference_simtype, find_type_refs, type_collections_for_lib
from angr.utils.vex import block_branch_ins_addr

from .function_parser import FunctionParser
from .transition_graph import TransitionGraph

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions.function_manager import FunctionManager
    from angr.project import Project

l = logging.getLogger(name=__name__)

_NODE_KINDS: dict[type, NodeKind] = {
    BlockNode: NodeKind.BLOCK,
    FuncNode: NodeKind.FUNC,
    HookNode: NodeKind.HOOK,
    SyscallNode: NodeKind.SYSCALL,
}
_EDGE_KINDS: dict[str, EdgeKind] = {
    "transition": EdgeKind.TRANSITION,
    "call": EdgeKind.CALL,
    "fake_return": EdgeKind.FAKE_RETURN,
    "return": EdgeKind.RETURN,
    "exception": EdgeKind.EXCEPTION,
    "syscall": EdgeKind.SYSCALL,
}
_EDGE_KIND_NAMES: dict[EdgeKind, str] = {v: k for k, v in _EDGE_KINDS.items()}
_ENDPOINT_KINDS: dict[str, EndpointKind] = {
    "call": EndpointKind.CALL,
    "return": EndpointKind.RETURN,
    "transition": EndpointKind.TRANSITION,
    "exception": EndpointKind.EXCEPTION,
}
_ENDPOINT_SORTS: dict[EndpointKind, str] = {v: k for k, v in _ENDPOINT_KINDS.items()}


def _node_key(node: CodeNode) -> tuple[NodeKind, int, int, bool]:
    kind = _NODE_KINDS.get(type(node))
    if kind is None:
        if isinstance(node, BlockNode):
            kind = NodeKind.BLOCK
        elif isinstance(node, SyscallNode):
            kind = NodeKind.SYSCALL
        elif isinstance(node, HookNode):
            kind = NodeKind.HOOK
        elif isinstance(node, FuncNode):
            kind = NodeKind.FUNC
        else:
            raise TypeError(f"{node!r} is not a CodeNode")
    size = node.size
    # hook nodes built from CFGNodes may carry size=None
    return kind, node.addr, 0 if size is None else size, bool(node.thumb)


def dirty_func(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        self._dirty = True
        return func(self, *args, **kwargs)

    return wrapper


class PrototypeSource(int, Enum):
    """
    An enumeration to represent the source of a function prototype. The values are ordered by certainty, with higher
    values indicating more certainty.
    """

    # guessed
    NONE = 0
    GUESSED = 1
    CCA_LOW = 2  # low-level IR (VEX or P-Code) based CCA
    # slightly more certain
    CALLSITE_LOW = 3  # low-level IR (VEX or P-Code) based call-site analysis
    CALLSITE_DECOMPILER = 6
    # more certain
    CCA_DECOMPILER = 20
    SIMPROC = 21  # SimProcedures
    SIGNATURES = 25  # function matching, e.g., FLIRT
    USER = 100


class FunctionInfo(UserDict):
    """
    A dictionary that updates the .dirty field of the Function object when modified.
    """

    def __init__(self, func: Function):
        super().__init__()
        self._func = func

    def __setitem__(self, key, value):
        if not isinstance(value, (str, int, float, bool, list, dict)):
            raise TypeError(
                "FunctionInfo only supports JSON-serializable values (str, int, float, bool, list, and dict)."
            )
        if not isinstance(key, str):
            raise TypeError("FunctionInfo only supports str keys.")
        self._func._dirty = True
        super().__setitem__(key, value)

    def __delitem__(self, key):
        self._func._dirty = True
        super().__delitem__(key)

    def copy(self, owner: Function) -> FunctionInfo:  # type: ignore[reportIncompatibleMethodOverride]
        new_info = FunctionInfo(owner)
        new_info.data = self.data.copy()
        return new_info

    def to_json(self) -> str:
        return json.dumps(self.data)

    @classmethod
    def from_json(cls, json_str: str, owner: Function) -> FunctionInfo:
        info = cls(owner)
        info.data = json.loads(json_str)
        return info


class Function(Serializable):
    """
    A representation of a function and various information about it.

    :ivar meta_only:            Whether this function only contains meta-information and in read-only mode.
    :ivar _dirty:                Whether this function has been modified since last serialization.
    :ivar evicted:              Whether this function has been evicted from FunctionManager to external storage.
    """

    __slots__ = (
        "__weakref__",
        "_argument_registers",
        "_argument_stack_variables",
        "_block_addrs_cache",
        "_calling_convention",
        "_cyclomatic_complexity",
        "_dirty",
        "_from_signature",
        "_function_manager",
        "_graph",
        "_info",
        "_is_alignment",
        "_is_plt",
        "_is_simprocedure",
        "_is_syscall",
        "_local_transition_graph",
        "_name",
        "_node_objs",
        "_project",
        "_prototype",
        "_prototype_libname",
        "_prototype_ref_warned",
        "_prototype_resolved",
        "_prototype_source",
        "_returning",
        "_tg",
        "addr",
        "binary_name",
        "bp_on_stack",
        "evicted",
        "is_default_name",
        "meta_only",
        "normalized",
        "previous_names",
        "ran_cca",
        "retaddr_on_stack",
        "sp_delta",
        "tags",
    )

    _prototype_source: PrototypeSource

    def __init__(
        self,
        function_manager: FunctionManager | None,
        addr: int,
        name=None,
        syscall=None,
        is_simprocedure: bool | None = None,
        binary_name=None,
        is_plt: bool | None = None,
        returning=None,
        alignment=False,
        calling_convention: SimCC | None = None,
        prototype: SimTypeFunction | None = None,
        prototype_libname: str | None = None,
        prototype_source: PrototypeSource | None = None,
        # deprecated
        is_prototype_guessed: bool = True,
    ):
        """
        Function constructor. If the optional parameters are not provided, they will be automatically determined upon
        the creation of a Function object.

        :param addr:            The address of the function.
        :param str name:        The name of the function.
        :param bool syscall:    Whether this function is a syscall or not.
        :param bool is_simprocedure:    Whether this function is a SimProcedure or not.
        :param str binary_name: Name of the binary where this function is.
        :param bool is_plt:     If this function is a PLT entry.
        :param bool returning:  If this function returns.
        :param bool alignment:  If this function acts as an alignment filler. Such functions usually only contain nops.
        """
        # the graph, block maps, endpoints, sites and call sites all live in the Rust store
        self._graph = FunctionGraph(addr)
        # the networkx view of the store, materialized on first read; None while nobody has read it
        self._tg: TransitionGraph | None = None
        # one canonical CodeNode object per store node id, created on demand
        self._node_objs: dict[int, CodeNode] = {}
        self._block_addrs_cache: set[int] | None = None
        self._local_transition_graph = None
        self.normalized = False

        self.addr = addr
        self._function_manager = function_manager
        self._is_syscall = False
        self._is_simprocedure = False
        self._is_alignment = alignment

        # These properties are set by VariableManager
        self.bp_on_stack = False
        self.retaddr_on_stack = False
        self.sp_delta = 0
        # Calling convention
        self._calling_convention = calling_convention
        # Function prototype. Prototypes may contain SimTypeRefs (e.g., when loaded from a library definition or an
        # angrdb); they are dereferenced lazily on the first read of .prototype.
        self._prototype = prototype
        self._prototype_resolved = False
        self._prototype_ref_warned = False
        self._prototype_libname = prototype_libname
        if prototype_source is None:
            self._prototype_source = (
                PrototypeSource.NONE
                if prototype is None
                else PrototypeSource.GUESSED
                if is_prototype_guessed
                else PrototypeSource.USER
            )
        else:
            self._prototype_source = prototype_source
        # Whether this function returns or not. `None` means it's not determined yet
        self._returning = None

        self._info = FunctionInfo(self)  # storing special information, like $gp values for MIPS32
        self.tags = ()  # store function tags. can be set manually by performing CodeTagging analysis.

        # Initialize _cyclomatic_complexity to None
        self._cyclomatic_complexity = None

        # TODO: Can we remove the following two members?
        # Register offsets of those arguments passed in registers
        self._argument_registers = []
        # Stack offsets of those arguments passed in stack variables
        self._argument_stack_variables = []

        self._project: Project | None = None  # will be initialized upon the first access to self.project

        self.ran_cca = False  # this is set by CompleteCallingConventions to avoid reprocessing failed functions
        self._dirty: bool = True
        self.meta_only: bool = False
        self.evicted: bool = False

        #
        # Initialize unspecified properties
        #

        if syscall is not None:
            self._is_syscall = syscall
        else:
            if self.project is None:
                raise ValueError(
                    "'syscall' must be specified if you do not specify a function manager for this new function."
                )

            # Determine whether this function is a syscall or not
            self._is_syscall = self.project.simos.is_syscall_addr(addr)

        # Determine whether this function is a SimProcedure
        if is_simprocedure is not None:
            self._is_simprocedure = is_simprocedure
        else:
            if self.project is None:
                raise ValueError(
                    "'is_simprocedure' must be specified if you do not specify a function manager for this new "
                    "function."
                )

            if self.is_syscall or self.project.is_hooked(addr):
                self._is_simprocedure = True

        # Determine if this function is a PLT entry
        if is_plt is not None:
            self._is_plt = is_plt
        else:
            if self._function_manager is not None:
                # use the faster cached version
                self._is_plt = self._function_manager.is_plt_cached(addr)
            else:
                # Whether this function is a PLT entry or not is primarily relying on the PLT detection in CLE; it may
                # also be updated (to True) during CFG recovery.
                if self.project is None:
                    raise ValueError(
                        "'is_plt' must be specified if you do not specify a function manager for this new function."
                    )
                self._is_plt = self.project.loader.find_plt_stub_name(addr) is not None

        # Determine the name of this function
        if name is None:
            self._name = self._get_initial_name()
        else:
            self.is_default_name = False
            self._name = name
        self.previous_names = []
        self._from_signature: str | None = None

        # Determine the name the binary where this function is.
        if binary_name is not None:
            self.binary_name = binary_name
        else:
            self.binary_name = self._get_initial_binary_name()

        # Determine returning status for SimProcedures and Syscalls
        if returning is not None:
            self.returning = returning
        else:
            if self.project is None:
                raise ValueError(
                    "'returning' must be specified if you do not specify a function manager for this new function."
                )

            self.returning = self._get_initial_returning()

        self._init_prototype_and_calling_convention()

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, v):
        if v == self._name:
            return
        if self._name not in self.previous_names:
            self.previous_names.append(self._name)
        if self._function_manager is not None:
            self._function_manager.function_name_changed(self.addr, self._name, v)
            self._function_manager._kb.labels[self.addr] = v
        self._name = v
        self.mark_dirty()

    @property
    def from_signature(self) -> str | None:
        return self._from_signature

    @from_signature.setter
    def from_signature(self, v: str | None):
        if self._from_signature == v:
            return
        self._from_signature = v
        self.mark_dirty()

        # update the cache
        if self._function_manager is not None:
            self._function_manager.set_from_signature(self.addr, v)

    @property
    def project(self) -> Project | None:
        if self._project is None and self._function_manager is not None:
            # try to set it from function manager
            self._project = self._function_manager._kb._project
        return self._project

    @property
    def returning(self):
        return self._returning

    @returning.setter
    def returning(self, v):
        if self._returning == v:
            return
        self._returning = v
        self.mark_dirty()

        # update the cache
        if self._function_manager is not None:
            self._function_manager.set_function_returning(self.addr, v)

    @property
    def calling_convention(self) -> SimCC | None:
        return self._calling_convention

    @calling_convention.setter
    @dirty_func
    def calling_convention(self, cc: SimCC | None):
        self._calling_convention = cc

    @property
    def prototype(self) -> SimTypeFunction | None:
        if self._prototype is None or self._prototype_resolved:
            return self._prototype
        self._resolve_prototype()
        return self._prototype

    def _resolve_prototype(self) -> None:
        """
        Dereference SimTypeRefs in the prototype using the loaded type collections. Unresolvable references are kept
        and retried on the next read.
        """
        assert self._prototype is not None
        refs = find_type_refs(self._prototype)
        if refs:
            proto = dereference_simtype(
                self._prototype, type_collections_for_lib(self._prototype_libname), keep_missing=True
            )
            assert isinstance(proto, SimTypeFunction)
            self._prototype = proto
            refs = find_type_refs(proto)
        if refs:
            if not self._prototype_ref_warned:
                self._prototype_ref_warned = True
                l.warning(
                    "Prototype of function %s references unknown types %s; load the type library that defines them.",
                    self.name,
                    sorted(refs),
                )
        else:
            self._prototype_resolved = True

    @prototype.setter
    @dirty_func
    def prototype(self, proto: SimTypeFunction | None):
        # if an argument does not have a name, assign it with the name of the exiting argument or a default name
        if (
            proto is not None
            and proto.args
            and (len(proto.arg_names) < len(proto.args) or any(not arg_name for arg_name in proto.arg_names))
        ):
            proto = proto.copy()
            arg_names = list(proto.arg_names)
            for i in range(len(proto.args)):
                if i < len(arg_names):
                    if not arg_names[i]:
                        if self._prototype is not None and i < len(self._prototype.arg_names):
                            arg_names[i] = self._prototype.arg_names[i]
                        else:
                            arg_names[i] = f"a{i}"
                else:
                    if self._prototype is not None and i < len(self._prototype.arg_names):
                        arg_names.append(self._prototype.arg_names[i])
                    else:
                        arg_names.append(f"a{i}")
            proto.arg_names = tuple(arg_names)
        self._prototype = proto
        self._prototype_resolved = False
        self._prototype_ref_warned = False

    @property
    def prototype_libname(self):
        return self._prototype_libname

    @prototype_libname.setter
    def prototype_libname(self, libname: str | None):
        if self._prototype_libname == libname:
            return
        self._prototype_libname = libname
        self._prototype_resolved = False
        self._prototype_ref_warned = False
        self.mark_dirty()

    @property
    def is_prototype_guessed(self) -> bool:
        return self._prototype_source in {PrototypeSource.NONE, PrototypeSource.GUESSED, PrototypeSource.CCA_LOW}

    @property
    def is_prototype_groundtruth(self) -> bool:
        """
        True if the prototype comes from outside of the decompiler (SimProcedures, signatures, or the user) and may be
        fed back into type inference as ground truth. Prototypes inferred by the decompiler itself are excluded so that
        re-decompiling a function does not freeze its own earlier guess.
        """
        return self._prototype is not None and self._prototype_source > PrototypeSource.CCA_DECOMPILER

    @property
    def prototype_source(self) -> PrototypeSource:
        return self._prototype_source

    @prototype_source.setter
    def prototype_source(self, source: PrototypeSource) -> None:
        if self._prototype_source == source:
            return
        self._prototype_source = source
        self.mark_dirty()

    @property
    def info(self) -> FunctionInfo:
        return self._info

    @info.setter
    @dirty_func
    def info(self, info: FunctionInfo | dict):
        if not isinstance(info, FunctionInfo):
            o = FunctionInfo(self)
            o.update(info)
            info = o
        self._info = info
        # update the owner
        self._info._func = self
        if self._function_manager is not None:
            self._function_manager.index_key_func_addrs(self)

    @property
    def is_plt(self) -> bool:
        return self._is_plt

    @is_plt.setter
    def is_plt(self, v: bool):
        if self._is_plt == v:
            return
        self._is_plt = v
        self.mark_dirty()

    @property
    def is_simprocedure(self) -> bool:
        return self._is_simprocedure

    @is_simprocedure.setter
    def is_simprocedure(self, v: bool):
        if self._is_simprocedure == v:
            return
        self._is_simprocedure = v
        self.mark_dirty()

    @property
    def is_syscall(self) -> bool:
        return self._is_syscall

    @is_syscall.setter
    def is_syscall(self, v: bool):
        if self._is_syscall == v:
            return
        self._is_syscall = v
        self.mark_dirty()

    @property
    def is_alignment(self) -> bool:
        return self._is_alignment

    @is_alignment.setter
    def is_alignment(self, v: bool):
        if self._is_alignment == v:
            return
        self._is_alignment = v
        self.mark_dirty()

    #
    # Graph store access
    #

    def _node_obj(self, idx: int) -> CodeNode:
        """
        The canonical CodeNode object for a store node id, created on demand.
        """
        obj = self._node_objs.get(idx)
        if obj is None:
            kind, addr, size, thumb = self._graph.node(idx)
            project = self.project
            if kind == NodeKind.BLOCK:
                obj = BlockNode(addr, size, thumb=thumb)
            elif kind == NodeKind.FUNC:
                obj = FuncNode(addr)
            elif kind == NodeKind.HOOK:
                obj = HookNode(addr, size, project.hooked_by(addr) if project is not None else None, thumb=thumb)
            else:
                obj = SyscallNode(
                    addr, size, project.simos.syscall_from_addr(addr) if project is not None else None, thumb=thumb
                )
            obj.set_owner(self)
            self._node_objs[idx] = obj
        return obj

    def _node_objs_of(self, idxs: Iterable[int]) -> list[CodeNode]:
        return [self._node_obj(i) for i in idxs]

    def _graph_node(self, node: CodeNode) -> int:
        """
        The store id of a node, inserting it into the graph if necessary (networkx add_edge/add_node semantics).
        """
        kind, addr, size, thumb = _node_key(node)
        idx, created = self._graph.add_node(kind, addr, size, thumb)
        if created or idx not in self._node_objs:
            node.set_owner(self)
            self._node_objs[idx] = node
        if self._tg is not None:
            self._tg._mirror_add_node(self._node_objs[idx])
        return idx

    def _find_node(self, node: CodeNode) -> int | None:
        return self._graph.find_node(*_node_key(node))

    def _add_edge(self, src: int, dst: int, kind: EdgeKind, present: int, **data) -> None:
        self._graph.add_edge(src, dst, kind, present, **data)
        if self._tg is not None:
            attrs = dict(data)
            if present & PRESENT_TYPE:
                attrs["type"] = _EDGE_KIND_NAMES[kind]
            self._tg._mirror_add_edge(self._node_obj(src), self._node_obj(dst), attrs)

    def _has_node(self, node: CodeNode) -> bool:
        idx = self._find_node(node)
        return idx is not None and self._graph.contains_node(idx)

    def _set_edge_outside(self, src: CodeNode, dst: CodeNode, outside: bool) -> None:
        s, d = self._find_node(src), self._find_node(dst)
        if s is None or d is None or not self._graph.has_edge(s, d):
            raise KeyError((src, dst))
        self._add_edge(s, d, EdgeKind.TRANSITION, PRESENT_OUTSIDE, outside=outside)
        self._local_transition_graph = None

    def _set_confirmed(self, src: int, dst: int, confirmed: bool) -> None:
        self._graph.set_edge_confirmed(src, dst, confirmed)
        if self._tg is not None:
            self._tg[self._node_obj(src)][self._node_obj(dst)]["confirmed"] = confirmed

    # write-through entry points used by TransitionGraph

    def _store_add_node(self, node: CodeNode) -> None:
        self._graph_node(node)
        self.mark_dirty()
        self._local_transition_graph = None

    def _store_add_edge(self, src: CodeNode, dst: CodeNode, attrs: dict) -> None:
        present = 0
        kind = EdgeKind.TRANSITION
        data = {}
        for key, value in attrs.items():
            if key == "type":
                present |= PRESENT_TYPE
                kind = _EDGE_KINDS[value]
            elif key == "outside":
                present |= PRESENT_OUTSIDE
                data["outside"] = bool(value)
            elif key == "ins_addr":
                present |= PRESENT_INS_ADDR
                data["ins_addr"] = value
            elif key == "stmt_idx":
                present |= PRESENT_STMT_IDX
                data["stmt_idx"] = value
            elif key == "confirmed":
                if value is not None:
                    present |= PRESENT_CONFIRMED
                    data["confirmed"] = bool(value)
            else:
                l.warning('Unexpected edge data key "%s" on the transition graph of %r.', key, self)
        self._graph.add_edge(self._graph_node(src), self._graph_node(dst), kind, present, **data)
        self.mark_dirty()
        self._local_transition_graph = None

    def _store_remove_node(self, node: CodeNode) -> None:
        idx = self._find_node(node)
        if idx is not None:
            self._graph.remove_node(idx)
        self.mark_dirty()
        self._local_transition_graph = None

    def _store_remove_edge(self, src: CodeNode, dst: CodeNode) -> None:
        s, d = self._find_node(src), self._find_node(dst)
        if s is not None and d is not None:
            self._graph.remove_edge(s, d)
        self.mark_dirty()
        self._local_transition_graph = None

    @property
    def transition_graph(self) -> TransitionGraph:
        """
        The networkx view of the transition graph, materialized on first read. In-place mutations are written
        through to the underlying store.
        """
        tg = self._tg
        if tg is None:
            tg = TransitionGraph(function=self)
            objs = self._node_obj
            tg._mirror_add_nodes(objs(i) for i in self._graph.nodes())
            tg._mirror_add_edges((objs(u), objs(v), d) for u, v, d in self._graph.edges_with_data())
            self._tg = tg
        return tg

    @property
    def startpoint(self) -> CodeNode | None:
        idx = self._graph.startpoint
        return None if idx is None else self._node_obj(idx)

    @startpoint.setter
    def startpoint(self, node: CodeNode | None) -> None:
        self._graph.startpoint = None if node is None else self._graph_node(node)

    @property
    def blocks(self):
        """
        An iterator of all local blocks in the current function.

        :return: angr.lifter.Block instances.
        """

        for block_addr, idx in self._graph.local_items():
            node = self._node_objs.get(idx)
            bytestr = node.bytestr if isinstance(node, BlockNode) else None
            with contextlib.suppress(SimEngineError, SimMemoryError):
                yield self.get_block(block_addr, size=self._graph.node_size(idx), byte_string=bytestr)

    @property
    def code_nodes(self) -> dict[int, CodeNode]:
        return {addr: self._node_obj(idx) for addr, idx in self._graph.local_items()}

    @property
    def cyclomatic_complexity(self):
        """
        The cyclomatic complexity of the function.

        Cyclomatic complexity is a software metric used to indicate the complexity of a program.
        It is a quantitative measure of the number of linearly independent paths through a program's source code.
        It is computed using the formula: M = E - N + 2P, where
        E = the number of edges in the graph,
        N = the number of nodes in the graph,
        P = the number of connected components.

        The cyclomatic complexity value is lazily computed and cached for future use.
        Initially this value is None until it is computed for the first time

        :return: The cyclomatic complexity of the function.
        :rtype: int
        """
        if self._cyclomatic_complexity is None:
            self._cyclomatic_complexity = self._graph.number_of_edges() - self._graph.number_of_nodes() + 2
        return self._cyclomatic_complexity

    @property
    def xrefs(self) -> Iterator[XRef]:
        """
        An iterator of all xrefs of the current function.

        :return: angr.knowledge_plugins.xrefs.xref.XRef instances.
        """
        assert self._function_manager is not None
        for block in self.blocks:
            yield from self._function_manager._kb.xrefs.get_xrefs_by_ins_addr_region(
                block.addr, block.addr + block.size
            )

    @property
    def block_addrs(self):
        """
        An iterator of all local block addresses in the current function.

        :return: block addresses.
        """

        return self._graph.local_addrs()

    @property
    def block_addrs_set(self):
        """
        Return a set of block addresses for a better performance of inclusion tests.

        :return: A set of block addresses.
        :rtype: set
        """

        if self._block_addrs_cache is None:
            self._block_addrs_cache = set(self._graph.local_addrs())
        return self._block_addrs_cache

    def get_block(self, addr: int, size: int | None = None, byte_string: bytes | None = None):
        """
        Getting a block out of the current function.

        :param int addr:    The address of the block.
        :param int size:    The size of the block. This is optional. If not provided, angr will load
        :param byte_string:
        :return:
        """
        if size is None and self._graph.is_local(addr):
            # we know the size
            size = self._graph.block_size(addr)

        assert self.project is not None
        block = self.project.factory.block(addr, size=size, byte_string=byte_string)
        if size is None:
            # update block_size dict
            self._graph.set_block_size(addr, block.size)
        return block

    # compatibility
    _get_block = get_block

    def get_block_size(self, addr: int) -> int | None:
        return self._graph.block_size(addr)

    @property
    def nodes(self) -> Iterable[CodeNode]:
        return self.transition_graph.nodes()

    def get_node(self, addr) -> BlockNode | None:
        idx = self._graph.block_node_at(addr)
        if idx is None:
            return None
        node = self._node_obj(idx)
        assert isinstance(node, BlockNode)
        return node

    @property
    def has_unresolved_jumps(self):
        assert self._function_manager is not None
        for addr in self.block_addrs:
            if addr in self._function_manager._kb.unresolved_indirect_jumps:
                b = self._function_manager._kb._project.factory.block(addr)
                if b.vex.jumpkind == "Ijk_Boring":
                    return True
        return False

    @property
    def has_unresolved_calls(self):
        assert self._function_manager is not None
        for addr in self.block_addrs:
            if addr in self._function_manager._kb.unresolved_indirect_jumps:
                b = self._function_manager._kb._project.factory.block(addr)
                if b.vex.jumpkind == "Ijk_Call":
                    return True
        return False

    @property
    def operations(self):
        """
        All of the operations that are done by this functions.
        """
        return [op for block in self.blocks for op in block.vex.operations]

    @property
    def code_constants(self):
        """
        All of the constants that are used by this functions's code.
        """
        # TODO: remove link register values
        return [const.value for block in self.blocks for const in block.vex.constants]

    @classmethod
    def _get_cmsg(cls):
        return function_pb2.Function()  # type: ignore  # pylint:disable=no-member

    def serialize_to_cmessage(self):
        return FunctionParser.serialize(self)

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        """
        :param cmsg:

        :return Function: The function instantiated out of the cmsg data.
        """
        return FunctionParser.parse_from_cmsg(cmsg, **kwargs)

    def string_references(self, minimum_length=2):
        """
        All of the constant string references used by this function.

        :param minimum_length:  The minimum length of strings to find (default is 1)
        :return:                A generator yielding tuples of (address, string) where is address
                                is the location of the string in memory.
        """

        assert self._function_manager is not None
        cfg = self._function_manager._kb.cfgs.get_most_accurate()
        if cfg is None:
            return

        for x in self.xrefs:
            if x.dst is None:
                continue
            try:
                md = cfg.memory_data[x.dst]
            except KeyError:
                continue
            if md.sort not in {MemoryDataSort.String, MemoryDataSort.UnicodeString}:
                continue
            if md.content is None:
                continue
            if len(md.content) < minimum_length:
                continue

            yield md.addr, md.content

    @property
    def local_runtime_values(self):
        """
        Tries to find all runtime values of this function which do not come from inputs.
        These values are generated by starting from a blank state and reanalyzing the basic blocks once each.
        Function calls are skipped, and back edges are never taken so these values are often unreliable,
        This function is good at finding simple constant addresses which the function will use or calculate.

        :return: a set of constants
        """
        constants = set()

        assert self.project is not None
        if not self.project.loader.main_object.contains_addr(self.addr):
            return constants

        # FIXME the old way was better for architectures like mips, but we need the initial irsb
        # reanalyze function with a new initial state (use persistent registers)
        # initial_state = self._function_manager._cfg.get_any_irsb(self.addr).initial_state
        # fresh_state = self.project.factory.blank_state(mode="fastpath")
        # for reg in initial_state.arch.persistent_regs + ['ip']:
        #     fresh_state.registers.store(reg, initial_state.registers.load(reg))

        # reanalyze function with a new initial state
        fresh_state = self.project.factory.blank_state(mode="fastpath")
        fresh_state.regs.ip = self.addr

        graph_addrs = {x.addr for x in self.graph.nodes() if isinstance(x, BlockNode)}

        # process the nodes in a breadth-first order keeping track of which nodes have already been analyzed
        analyzed = set()
        q = [fresh_state]
        analyzed.add(fresh_state.solver.eval(fresh_state.ip))
        while len(q) > 0:
            state = q.pop()
            # make sure its in this function
            if state.solver.eval(state.ip) not in graph_addrs:
                continue
            # don't trace into simprocedures
            if self.project.is_hooked(state.solver.eval(state.ip)):
                continue
            # don't trace outside of the binary
            if not self.project.loader.main_object.contains_addr(state.solver.eval(state.ip)):
                continue
            # don't trace unreachable blocks
            if state.history.jumpkind in {
                "Ijk_EmWarn",
                "Ijk_NoDecode",
                "Ijk_MapFail",
                "Ijk_NoRedir",
                "Ijk_SigTRAP",
                "Ijk_SigSEGV",
                "Ijk_ClientReq",
            }:
                continue

            curr_ip = state.solver.eval(state.ip)

            # get runtime values from logs of successors
            successors = self.project.factory.successors(state)
            for succ in successors.flat_successors + successors.unsat_successors:
                for a in succ.history.recent_actions:
                    for ao in a.all_objects:
                        if not isinstance(ao.ast, claripy.ast.Base):
                            constants.add(ao.ast)
                        elif not ao.ast.symbolic:
                            constants.add(succ.solver.eval(ao.ast))

                # add successors to the queue to analyze
                if not succ.solver.symbolic(succ.ip):
                    succ_ip = succ.solver.eval(succ.ip)
                    if succ_ip in self and succ_ip not in analyzed:
                        analyzed.add(succ_ip)
                        q.insert(0, succ)

            # force jumps to missing successors
            # (this is a slightly hacky way to force it to explore all the nodes in the function)
            node = self.get_node(curr_ip)
            if node is None:
                # the node does not exist. maybe it's not a block node.
                continue
            missing = {x.addr for x in list(self.graph.successors(node))} - analyzed
            for succ_addr in missing:
                l.info("Forcing jump to missing successor: %#x", succ_addr)
                if succ_addr not in analyzed:
                    all_successors = (
                        successors.unconstrained_successors + successors.flat_successors + successors.unsat_successors
                    )
                    if len(all_successors) > 0:
                        # set the ip of a copied successor to the successor address
                        succ = all_successors[0].copy()
                        succ.ip = succ_addr
                        analyzed.add(succ_addr)
                        q.insert(0, succ)
                    else:
                        l.warning("Could not reach successor: %#x", succ_addr)

        return constants

    @property
    def num_arguments(self):
        return len(self._argument_registers) + len(self._argument_stack_variables)

    def __contains__(self, val):
        if isinstance(val, int):
            return self._graph.has_block_size(val)
        return False

    def __str__(self):
        return (
            f"Function {self.name} [{self.addr:#x}]\n"
            f"  Syscall: {self.is_syscall}\n"
            f"  SP difference: {self.sp_delta}\n"
            f"  Has return: {self.has_return}\n"
            f"  Returning: {'Unknown' if self.returning is None else self.returning}\n"
            f"  Alignment: {self.is_alignment}\n"
            f"  Arguments: reg: {self._argument_registers}, stack: {self._argument_stack_variables}\n"
            f"  Blocks: [{', '.join(f'{i:#x}' for i in self.block_addrs)}]\n"
            f"  Cyclomatic Complexity: {self.cyclomatic_complexity}\n"
            f"  Calling convention: {self.calling_convention}"
        )

    def __repr__(self):
        if self.is_syscall:
            return f"<Syscall function {self.name} ({hex(self.addr) if isinstance(self.addr, int) else self.addr})>"
        return f"<Function {self.name} ({hex(self.addr) if isinstance(self.addr, int) else self.addr})>"

    def __setstate__(self, state):
        if "_graph" not in state:
            self._set_legacy_state(state)
            return
        for k, v in state.items():
            setattr(self, k, v)

    def _set_legacy_state(self, state: dict) -> None:
        """
        Restore a Function pickled before the graph moved into the Rust store.
        """
        graph_keys = {
            "transition_graph",
            "_local_transition_graph",
            "_addr_to_block_node",
            "_block_sizes",
            "_local_blocks",
            "_local_block_addrs",
            "_ret_sites",
            "_jumpout_sites",
            "_callout_sites",
            "_retout_sites",
            "_endpoints",
            "_call_sites",
            "startpoint",
        }
        for k, v in state.items():
            if k not in graph_keys:
                setattr(self, k, v)
        self._graph = FunctionGraph(self.addr)
        self._tg = None
        self._node_objs = {}
        self._block_addrs_cache = None
        self._local_transition_graph = None
        for node in state["_local_blocks"].values():
            self._register(True, node, update_func_block_count=False)
        tg = self.transition_graph
        tg.add_nodes_from(state["transition_graph"].nodes())
        tg.add_edges_from(state["transition_graph"].edges(data=True))
        for addr, size in state["_block_sizes"].items():
            self._graph.set_block_size(addr, size)
        for node in state["_addr_to_block_node"].values():
            self._graph.set_block_node_at(node.addr, self._graph_node(node))
        for sort, nodes in state["_endpoints"].items():
            for node in nodes:
                self._add_endpoint(node, sort)
        for key, kind in (
            ("_ret_sites", SiteKind.RET),
            ("_jumpout_sites", SiteKind.JUMPOUT),
            ("_callout_sites", SiteKind.CALLOUT),
            ("_retout_sites", SiteKind.RETOUT),
        ):
            for node in state[key]:
                self._graph.add_site(self._graph_node(node), kind)
        for addr, (target, ret) in state["_call_sites"].items():
            self._graph.add_call_site(addr, target, ret)
        self.startpoint = state["startpoint"]

    def __getstate__(self):
        # the networkx views and node objects are caches. don't pickle them
        d = {k: getattr(self, k) for k in self.__slots__ if k != "__weakref__"}
        d["_local_transition_graph"] = None
        d["_tg"] = None
        d["_node_objs"] = {}
        d["_block_addrs_cache"] = None
        d["_project"] = None
        d["_function_manager"] = None
        return d

    @property
    def endpoints(self) -> list[CodeNode]:
        return list(itertools.chain.from_iterable(self.endpoints_with_type.values()))

    @property
    def endpoints_with_type(self) -> defaultdict[str, set[CodeNode]]:
        d: defaultdict[str, set[CodeNode]] = defaultdict(set)
        for kind, sort in _ENDPOINT_SORTS.items():
            idxs = self._graph.endpoints(kind)
            if idxs:
                d[sort] = set(self._node_objs_of(idxs))
        return d

    @property
    def ret_sites(self) -> list[CodeNode]:
        return self._node_objs_of(self._graph.sites(SiteKind.RET))

    @property
    def jumpout_sites(self) -> list[CodeNode]:
        return self._node_objs_of(self._graph.sites(SiteKind.JUMPOUT))

    @property
    def retout_sites(self) -> list[CodeNode]:
        return self._node_objs_of(self._graph.sites(SiteKind.RETOUT))

    @property
    def callout_sites(self) -> list[CodeNode]:
        return self._node_objs_of(self._graph.sites(SiteKind.CALLOUT))

    @property
    def size(self):
        return self._graph.local_size()

    @property
    def binary(self):
        """
        Get the object this function belongs to.
        :return: The object this function belongs to.
        """
        assert self.project is not None
        return self.project.loader.find_object_containing(self.addr, membership_check=False)

    @property
    def offset(self) -> int:
        """
        :return: the function's binary offset (i.e., non-rebased address)
        """
        assert self.binary is not None
        return self.addr - self.binary.mapped_base

    @property
    def symbol(self) -> Symbol | None:
        """
        :return: the function's Symbol, if any
        """
        assert self.binary is not None
        return self.binary.loader.find_symbol(self.addr)

    @property
    def pseudocode(self) -> str | None:
        """
        :return: the function's pseudocode
        """
        if self.project is None:
            l.error("Cannot generate pseudocode because the function is not associated with any angr project.")
            return None
        assert self._function_manager is not None
        dec = self.project.analyses.Decompiler(self, cfg=self._function_manager._kb.cfgs.get_most_accurate())
        return dec.codegen.text if dec.codegen else None

    @property
    def dirty(self) -> bool:
        return self._dirty

    def mark_dirty(self) -> None:
        self._dirty = True

    @dirty_func
    def add_jumpout_site(self, node: CodeNode):
        """
        Add a custom jumpout site.

        :param node:    The address of the basic block that control flow leaves during this transition.
        :return:        None
        """

        idx = self._register(True, node)
        self._graph.add_site(idx, SiteKind.JUMPOUT)
        self._graph.add_endpoint(idx, EndpointKind.TRANSITION)

    @dirty_func
    def add_retout_site(self, node: CodeNode):
        """
        Add a custom retout site.

        Retout (returning to outside of the function) sites are very rare. It mostly occurs during CFG recovery when we
        incorrectly identify the beginning of a function in the first iteration, and then correctly identify that
        function later in the same iteration (function alignments can lead to this bizarre case). We will mark all edges
        going out of the header of that function as a outside edge, because all successors now belong to the
        incorrectly-identified function. This identification error will be fixed in the second iteration of CFG
        recovery. However, we still want to keep track of jumpouts/retouts during the first iteration so other logic in
        CFG recovery still work.

        :param node: The address of the basic block that control flow leaves the current function after a call.
        :return:     None
        """

        idx = self._register(True, node)
        self._graph.add_site(idx, SiteKind.RETOUT)
        self._graph.add_endpoint(idx, EndpointKind.RETURN)

    def _get_initial_name(self):
        """
        Determine the most suitable name of the function.

        :return:    The initial function name.
        :rtype:     string
        """

        name = None
        addr = self.addr

        self.is_default_name = False
        # Try to get a name from existing labels
        if self._function_manager is not None and addr in self._function_manager._kb.labels:
            name = self._function_manager._kb.labels[addr]

        # try to get the name from a hook
        if name is None and self.project is not None:
            project = self.project
            if project.is_hooked(addr):
                hooker = project.hooked_by(addr)
                if hooker is not None:
                    name = hooker.display_name
            elif project.simos.is_syscall_addr(addr):
                syscall_inst = project.simos.syscall_from_addr(addr)
                if syscall_inst is not None:
                    name = syscall_inst.display_name

        # generate an IDA-style sub_X name
        if name is None:
            self.is_default_name = True
            name = f"sub_{addr:x}"

        return name

    def _get_initial_binary_name(self) -> str | None:
        """
        Determine the name of the binary where this function is.

        :return: None
        """

        binary_name = None

        # if this function is a simprocedure but not a syscall, use its library name as
        # its binary name
        # if it is a syscall, fall back to use self.binary.binary which explicitly says cle##kernel
        if self.project and self.is_simprocedure and not self.is_syscall:
            hooker = self.project.hooked_by(self.addr)
            if hooker is not None:
                binary_name = hooker.library_name

        if binary_name is None:
            if self._function_manager is not None:
                # use the faster cached version
                binary_name = self._function_manager.get_binary_name_cached(self.addr)
            else:
                if self.binary is not None and self.binary.binary:
                    binary_name = os.path.basename(self.binary.binary)

        return binary_name

    def _get_initial_returning(self):
        """
        Determine if this function returns or not *if it is hooked by a SimProcedure or a user hook*.

        :return:    True if the hooker returns, False otherwise.
        :rtype:     bool
        """

        hooker = None
        assert self.project is not None
        if self.is_syscall:
            hooker = self.project.simos.syscall_from_addr(self.addr)
        elif self.is_simprocedure:
            hooker = self.project.hooked_by(self.addr)
        if hooker:
            if hasattr(hooker, "DYNAMIC_RET") and hooker.DYNAMIC_RET:
                return True
            return hooker.returns

        # Cannot determine
        return None

    @dirty_func
    def _init_prototype_and_calling_convention(self) -> None:
        """
        Initialize prototype and calling convention from a SimProcedure, if available.
        """
        hooker = None
        if self.is_syscall and self.project is not None and self.project.simos.is_syscall_addr(self.addr):
            hooker = self.project.simos.syscall_from_addr(self.addr)
        elif self.is_simprocedure and self.project is not None:
            hooker = self.project.hooked_by(self.addr)
        if hooker is None or hooker.guessed_prototype:
            return

        if hooker.prototype:
            self.prototype_libname = hooker.library_name
            self.prototype = hooker.prototype
            self.prototype_source = PrototypeSource.SIMPROC

        cc = hooker.cc
        if cc is None and self.project is not None:
            arch = self.project.arch
            if arch.name in DEFAULT_CC:
                cc_cls = default_cc_for_project(self.project)
                if cc_cls is not None:
                    cc = cc_cls(arch)
        self.calling_convention = cc

    @dirty_func
    def _clear_transition_graph(self):
        self._graph = FunctionGraph(self.addr)
        self._tg = None
        self._node_objs = {}
        self._block_addrs_cache = None
        self._local_transition_graph = None

    @dirty_func
    def _confirm_fakeret(self, src, dst):
        s, d = self._find_node(src), self._find_node(dst)
        if s is None or d is None or not self._graph.has_edge(s, d):
            raise AngrValueError(f"FakeRet edge ({src}, {dst}) is not in transition graph.")

        if self._graph.edge_kind(s, d) != EdgeKind.FAKE_RETURN:
            raise AngrValueError(f"Edge ({src}, {dst}) is not a FakeRet edge")

        # it's confirmed. register the node if needed
        if not self._graph.edge_is_outside(s, d):
            self._register(True, dst)

        self._set_confirmed(s, d, True)

    @dirty_func
    def _transit_to(
        self,
        from_node: CodeNode,
        to_node,
        outside=False,
        ins_addr=None,
        stmt_idx=None,
        is_exception=False,
        update_func_block_count: bool = True,
    ):
        """
        Registers an edge between basic blocks in this function's transition graph.
        Arguments are CodeNode objects.

        :param from_node            The address of the basic block that control
                                    flow leaves during this transition.
        :param to_node              The address of the basic block that control
                                    flow enters during this transition.
        :param bool outside:        If this is a transition to another function, e.g. tail call optimization
        :return: None
        """

        src = self._register(True, from_node, update_func_block_count=update_func_block_count)
        dst = None
        if to_node is not None:
            dst = self._register(not outside, to_node, update_func_block_count=update_func_block_count)
        if outside:
            self._graph.add_site(src, SiteKind.JUMPOUT)

        kind = EdgeKind.EXCEPTION if is_exception else EdgeKind.TRANSITION
        if dst is not None:
            self._add_edge(
                src,
                dst,
                kind,
                PRESENT_TYPE | PRESENT_OUTSIDE | PRESENT_INS_ADDR | PRESENT_STMT_IDX,
                outside=outside,
                ins_addr=ins_addr,
                stmt_idx=stmt_idx,
            )

        if outside:
            # this node is an endpoint of the current function
            self._graph.add_endpoint(src, EndpointKind.EXCEPTION if is_exception else EndpointKind.TRANSITION)

        # clear the cache
        self._local_transition_graph = None

    @dirty_func
    def _call_to(
        self,
        from_node,
        to_func: FuncNode | HookNode,
        ret_node,
        stmt_idx=None,
        ins_addr=None,
        return_to_outside=False,
        syscall: bool = False,
        update_func_block_count: bool = True,
    ):
        """
        Registers an edge between the caller basic block and callee function.

        :param from_addr:   The basic block that control flow leaves during the transition.
        :type  from_addr:   angr.knowledge.CodeNode
        :param to_func:     The function that we are calling, represented as a FuncNode.
        :param ret_node     The basic block that control flow should return to after the
                            function call.
        :type  to_func:     angr.knowledge.CodeNode or None
        :param stmt_idx:    Statement ID of this call.
        :type  stmt_idx:    int, str or None
        :param ins_addr:    Instruction address of this call.
        :type  ins_addr:    int or None
        """

        src = self._register(True, from_node, update_func_block_count=update_func_block_count)
        dst = self._graph_node(to_func)
        self._add_edge(
            src,
            dst,
            EdgeKind.SYSCALL if syscall else EdgeKind.CALL,
            PRESENT_TYPE | PRESENT_STMT_IDX | PRESENT_INS_ADDR,
            stmt_idx=stmt_idx,
            ins_addr=ins_addr,
        )
        if ret_node is not None and not syscall:
            self._register(return_to_outside is False, ret_node, update_func_block_count=update_func_block_count)
            self._fakeret_to(
                from_node, ret_node, to_outside=return_to_outside, update_func_block_count=update_func_block_count
            )

        self._local_transition_graph = None

    @dirty_func
    def _fakeret_to(self, from_node, to_node, confirmed=None, to_outside=False, update_func_block_count: bool = True):
        src = self._register(True, from_node, update_func_block_count=update_func_block_count)
        if confirmed:
            dst = self._register(not to_outside, to_node, update_func_block_count=update_func_block_count)
        else:
            dst = self._graph_node(to_node)

        if confirmed is None:
            self._add_edge(src, dst, EdgeKind.FAKE_RETURN, PRESENT_TYPE | PRESENT_OUTSIDE, outside=to_outside)
        else:
            self._add_edge(
                src,
                dst,
                EdgeKind.FAKE_RETURN,
                PRESENT_TYPE | PRESENT_OUTSIDE | PRESENT_CONFIRMED,
                outside=to_outside,
                confirmed=confirmed,
            )

        self._local_transition_graph = None

    @dirty_func
    def _remove_fakeret(self, from_node, to_node):
        self._remove_edge(from_node, to_node)

    def _remove_edge(self, from_node: CodeNode, to_node: CodeNode) -> None:
        s, d = self._find_node(from_node), self._find_node(to_node)
        if s is None or d is None or not self._graph.remove_edge(s, d):
            raise networkx.NetworkXError(f"The edge {from_node}-{to_node} is not in the graph.")
        if self._tg is not None:
            self._tg._mirror_remove_edge(self._node_obj(s), self._node_obj(d))
        self._local_transition_graph = None

    @dirty_func
    def _return_from_call(
        self, from_func: FuncNode | HookNode, to_node, to_outside=False, confirm_fakeret: bool = True
    ):
        src = self._graph_node(from_func)
        dst = self._graph_node(to_node)
        self._add_edge(src, dst, EdgeKind.RETURN, PRESENT_TYPE | PRESENT_OUTSIDE, outside=to_outside)
        if confirm_fakeret:
            for pred in self._graph.predecessors(dst):
                if self._graph.edge_kind(pred, dst) == EdgeKind.FAKE_RETURN:
                    self._set_confirmed(pred, dst, True)

        self._local_transition_graph = None

    def update_func_block_count(self) -> None:
        """Update the cached block count of this function in the function manager."""
        if self._function_manager is not None:
            self._function_manager.set_func_block_count(self.addr, self._graph.local_count())

    def _register(self, is_local: bool, node: CodeNode, update_func_block_count: bool = True) -> int:
        """
        Register a node with the function and return its store id. The first object registered for a fresh id
        becomes the canonical CodeNode object for it.
        """
        kind, addr, size, thumb = _node_key(node)
        idx, created, new_local, changed = self._graph.register_node(is_local, kind, addr, size, thumb)
        if not changed:
            return idx
        if created or idx not in self._node_objs:
            node.set_owner(self)
            self._node_objs[idx] = node
        self.mark_dirty()
        self._local_transition_graph = None
        if new_local:
            if self._block_addrs_cache is not None:
                self._block_addrs_cache.add(addr)
            if update_func_block_count:
                self.update_func_block_count()
        if self._tg is not None and self._graph.contains_node(idx):
            self._tg._mirror_add_node(self._node_objs[idx])
        return idx

    def _register_node(self, is_local: bool, node: CodeNode, update_func_block_count: bool = True) -> CodeNode:
        return self._node_obj(self._register(is_local, node, update_func_block_count=update_func_block_count))

    @dirty_func
    def _add_return_site(self, return_site: CodeNode):
        """
        Registers a basic block as a site for control flow to return from this function.

        :param return_site:     The block node that ends with a return.
        """
        idx = self._register(True, return_site)

        self._graph.add_site(idx, SiteKind.RET)
        # A return site must be an endpoint of the function - you cannot continue execution of the current function
        # after returning
        self._graph.add_endpoint(idx, EndpointKind.RETURN)

    @dirty_func
    def _add_call_site(self, call_site_addr, call_target_addr, retn_addr):
        """
        Registers a basic block as calling a function and returning somewhere.

        :param call_site_addr:       The address of a basic block that ends in a call.
        :param call_target_addr:     The address of the target of said call.
        :param retn_addr:            The address that said call will return to.
        """
        self._graph.add_call_site(call_site_addr, call_target_addr, retn_addr)

    @dirty_func
    def _add_endpoint(self, endpoint_node, sort):
        """
        Registers an endpoint with a type of `sort`. The type can be one of the following:
        - call: calling a function that does not return
        - return: returning from the current function
        - transition: a jump/branch targeting a different function

        A block can act as two different sorts of endpoints, e.g. a block that ends with a `lock xadd` retry loop
        followed by a `retn` is both a return endpoint and a transition endpoint.

        :param endpoint_node:       The endpoint node.
        :param sort:                Type of the endpoint.
        :return:                    None
        """

        self._graph.add_endpoint(self._graph_node(endpoint_node), _ENDPOINT_KINDS[sort])

    def mark_nonreturning_calls_endpoints(self):
        """
        Iterate through all call edges in transition graph. For each call a non-returning function, mark the source
        basic block as an endpoint.

        This method should only be executed once all functions are recovered and analyzed by CFG recovery, so we know
        whether each function returns or not.

        :return: None
        """

        assert self._function_manager is not None

        graph = self._graph
        for src, dst in graph.edges_of_kind(EdgeKind.CALL):
            func_addr = graph.node_addr(dst)
            if self._function_manager.contains_addr(func_addr) and self._function_manager.is_func_nonreturning(
                func_addr
            ):
                # the target function does not return
                the_node = graph.block_node_at(graph.node_addr(src))
                if the_node is not None:
                    graph.add_site(the_node, SiteKind.CALLOUT)
                    graph.add_endpoint(the_node, EndpointKind.CALL)
                    self.mark_dirty()

    @property
    def _call_sites(self) -> dict[int, tuple[int | None, int | None]]:
        return {addr: (target, ret) for addr, target, ret in self._graph.call_sites()}

    def outgoing_function_targets(self) -> list[int]:
        """
        Addresses of the functions this function calls or jumps out to: callee nodes plus the targets of outside
        transition edges. This is what the call graph is built from.
        """
        return [addr for addr, _ in self._graph.outgoing_function_targets()]

    def get_call_sites(self) -> Iterable[int]:
        """
        Gets a list of all the basic blocks that end in calls.

        :return:                    A view of the addresses of the blocks that end in calls.
        """
        return self._graph.call_site_addrs()

    def get_call_target(self, callsite_addr):
        """
        Get the target of a call.

        :param callsite_addr:       The address of a basic block that ends in a call.
        :return:                    The target of said call, or None if callsite_addr is not a
                                    callsite.
        """
        site = self._graph.call_site(callsite_addr) if isinstance(callsite_addr, int) else None
        return None if site is None else site[0]

    def get_call_return(self, callsite_addr):
        """
        Get the hypothetical return address of a call.

        :param callsite_addr:       The address of the basic block that ends in a call.
        :return:                    The likely return target of said call, or None if callsite_addr
                                    is not a callsite.
        """
        site = self._graph.call_site(callsite_addr) if isinstance(callsite_addr, int) else None
        return None if site is None else site[1]

    @property
    def graph(self) -> networkx.DiGraph[CodeNode]:
        """
        Get a local transition graph. A local transition graph is a transition graph that only contains nodes that
        belong to the current function. All edges, except for the edges going out from the current function or coming
        from outside the current function, are included.

        The generated graph is cached in self._local_transition_graph.

        :return:    A local transition graph.
        :rtype:     networkx.DiGraph
        """

        if self._local_transition_graph is not None:
            return self._local_transition_graph

        objs = self._node_obj
        g = networkx.classes.digraph.DiGraph()
        startpoint = self._graph.startpoint
        if startpoint is not None:
            g.add_node(objs(startpoint))
        g.add_nodes_from(objs(idx) for _, idx in self._graph.local_items())
        g.add_edges_from((objs(u), objs(v), d) for u, v, d in self._graph.local_edges_with_data())

        self._local_transition_graph = g

        return g

    def graph_ex(self, exception_edges=True) -> networkx.DiGraph[CodeNode]:
        """
        Get a local transition graph with a custom configuration. A local transition graph is a transition graph that
        only contains nodes that belong to the current function. This method allows user to exclude certain types of
        edges together with the nodes that are only reachable through such edges, such as exception edges.

        The generated graph is not cached.

        :param bool exception_edges:    Should exception edges and the nodes that are only reachable through exception
                                        edges be kept.
        :return:                        A local transition graph with a special configuration.
        :rtype:                         networkx.DiGraph
        """

        # graph_ex() should not impact any already cached graph
        old_cached_graph = self._local_transition_graph
        graph = self.graph
        self._local_transition_graph = old_cached_graph  # restore the cached graph

        # fast path
        if exception_edges:
            return graph

        # BFS on local graph but ignoring certain types of graphs
        g = networkx.classes.digraph.DiGraph()
        queue = [n for n in graph if n is self.startpoint or graph.in_degree[n] == 0]
        traversed = set(queue)

        while queue:
            node = queue.pop(0)

            g.add_node(node)
            for _, dst, edge_data in graph.out_edges(node, data=True):
                edge_type = edge_data.get("type", None)
                if not exception_edges and edge_type == "exception":
                    # ignore this edge
                    continue
                g.add_edge(node, dst, **edge_data)

                if dst not in traversed:
                    traversed.add(dst)
                    queue.append(dst)

        return g

    def transition_graph_ex(self, exception_edges=True):
        """
        Get a transition graph with a custom configuration. This method allows user to exclude certain types of edges
        together with the nodes that are only reachable through such edges, such as exception edges.

        The generated graph is not cached.

        :param bool exception_edges:    Should exception edges and the nodes that are only reachable through exception
                                        edges be kept.
        :return:                        A local transition graph with a special configuration.
        :rtype:                         networkx.DiGraph
        """

        graph = self.transition_graph

        # fast path
        if exception_edges:
            return graph

        # BFS on local graph but ignoring certain types of graphs
        g = networkx.classes.digraph.DiGraph()
        queue = [n for n in graph if n is self.startpoint or graph.in_degree[n] == 0]
        traversed = set(queue)

        while queue:
            node = queue.pop(0)
            traversed.add(node)

            g.add_node(node)
            for _, dst, edge_data in graph.out_edges(node, data=True):
                edge_type = edge_data.get("type", None)
                if not exception_edges and edge_type == "exception":
                    # ignore this edge
                    continue
                g.add_edge(node, dst, **edge_data)

                if dst not in traversed:
                    traversed.add(dst)
                    queue.append(dst)

        return g

    def subgraph(self, ins_addrs):
        """
        Generate a sub control flow graph of instruction addresses based on self.graph

        :param iterable ins_addrs: A collection of instruction addresses that should be included in the subgraph.
        :return networkx.DiGraph: A subgraph.
        """

        # find all basic blocks that include those instructions
        blocks = []
        block_addr_to_insns = {}

        for b in self.code_nodes.values():
            # TODO: should I call get_blocks?
            block = self.get_block(b.addr, size=b.size, byte_string=b.bytestr if isinstance(b, BlockNode) else None)
            common_insns = set(block.instruction_addrs).intersection(ins_addrs)
            if common_insns:
                blocks.append(b)
                block_addr_to_insns[b.addr] = sorted(common_insns)

        # subgraph = networkx.subgraph(self.graph, blocks)
        subgraph = self.graph.subgraph(blocks).copy()
        assert isinstance(subgraph, networkx.DiGraph)
        g = networkx.classes.digraph.DiGraph()

        for n in subgraph.nodes():
            insns = block_addr_to_insns[n.addr]

            in_edges = subgraph.in_edges(n)
            # out_edges = subgraph.out_edges(n)
            # the first instruction address should be included
            if len(in_edges) > 1 and n.addr not in insns:
                insns = [n.addr, *insns]

            for src, _ in in_edges:
                last_instr = block_addr_to_insns[src.addr][-1]
                g.add_edge(last_instr, insns[0])

            for i in range(len(insns) - 1):
                g.add_edge(insns[i], insns[i + 1])

        return g

    def instruction_size(self, insn_addr):
        """
        Get the size of the instruction specified by `insn_addr`.

        :param int insn_addr: Address of the instruction
        :return int: Size of the instruction in bytes, or None if the instruction is not found.
        """

        for block in self.blocks:
            if insn_addr in block.instruction_addrs:
                index = block.instruction_addrs.index(insn_addr)
                if index == len(block.instruction_addrs) - 1:
                    # the very last instruction
                    size = block.addr + block.size - insn_addr
                else:
                    size = block.instruction_addrs[index + 1] - insn_addr
                return size

        return None

    def addr_to_instruction_addr(self, addr):
        """
        Obtain the address of the instruction that covers @addr.

        :param int addr:    An address.
        :return:            Address of the instruction that covers @addr, or None if this addr is not covered by any
                            instruction of this function.
        :rtype:             int or None
        """

        # TODO: Replace the linear search with binary search
        for b in self.blocks:
            if b.addr <= addr < b.addr + b.size:
                # found it
                for i, instr_addr in enumerate(b.instruction_addrs):
                    if (i < len(b.instruction_addrs) - 1 and instr_addr <= addr < b.instruction_addrs[i + 1]) or (
                        i == len(b.instruction_addrs) - 1 and instr_addr <= addr
                    ):
                        return instr_addr
                # Not covered by any instruction... why?
                return None
        return None

    def dbg_print(self):
        """
        Returns a representation of the list of basic blocks in this function.
        """
        return "[{}]".format(", ".join((f"{n.addr:#08x}") for n in self.transition_graph.nodes()))

    def dbg_draw(self, filename):
        """
        Draw the graph and save it to a PNG file.
        """
        from matplotlib import pyplot  # pylint: disable=import-error,import-outside-toplevel,consider-using-from-import
        from networkx.drawing.nx_agraph import graphviz_layout  # pylint: disable=import-error,import-outside-toplevel

        tmp_graph = networkx.classes.digraph.DiGraph()
        ret_site_addrs = {n.addr for n in self.ret_sites}
        call_site_addrs = set(self.get_call_sites())
        for from_block, to_block in self.transition_graph.edges():
            node_a = f"{from_block.addr:#08x}"
            node_b = f"{to_block.addr:#08x}"
            if to_block.addr in ret_site_addrs:
                node_b += "[Ret]"
            if from_block.addr in call_site_addrs:
                node_a += "[Call]"
            tmp_graph.add_edge(node_a, node_b)
        pos = graphviz_layout(tmp_graph, prog="fdp")  # pylint: disable=no-member
        networkx.draw(tmp_graph, pos, node_size=1200)
        pyplot.savefig(filename)

    @dirty_func
    def _add_argument_register(self, reg_offset):
        """
        Registers a register offset as being used as an argument to the function.

        :param reg_offset:          The offset of the register to register.
        """
        assert self._function_manager is not None
        if reg_offset in self._function_manager._arg_registers and reg_offset not in self._argument_registers:
            self._argument_registers.append(reg_offset)

    @dirty_func
    def _add_argument_stack_variable(self, stack_var_offset):
        if stack_var_offset not in self._argument_stack_variables:
            self._argument_stack_variables.append(stack_var_offset)

    @property
    def arguments(self):
        if self.calling_convention is None:
            return self._argument_registers + self._argument_stack_variables
        if self.prototype is None:
            return []
        return self.calling_convention.arg_locs(self.prototype)

    @property
    def has_return(self):
        return len(self._graph.sites(SiteKind.RET)) > 0

    @property
    def callable(self):
        assert self.project is not None
        return self.project.factory.callable(self.addr)

    @dirty_func
    def normalize(self):
        """
        Make sure all basic blocks in the transition graph of this function do not overlap. You will end up with a CFG
        that IDA Pro generates.

        This method does not touch the CFG result. You may call CFG{Emulated, Fast}.normalize() for that matter.

        :return: None
        """
        assert self.project is not None

        # let's put a check here
        if self.startpoint is None:
            # this function is empty
            l.debug("Unexpected error: %s does not have any blocks. normalize() fails.", repr(self))
            return

        project = self.project

        def branch_ins_addr(addr: int, size: int) -> int | None:
            block = project.factory.block(addr, size=size)
            return block_branch_ins_addr(block.instruction_addrs, block.addr, block.size, project.arch)

        self._graph.normalize(is_arm_arch(project.arch), branch_ins_addr)

        # Clear the caches
        self._tg = None
        self._local_transition_graph = None
        self._block_addrs_cache = None

        self.normalized = True

    def find_declaration(self, ignore_binary_name: bool = False, binary_name_hint: str | None = None) -> bool:
        """
        Find the most likely function declaration from the embedded collection of prototypes, set it to self.prototype,
        and update self.calling_convention with the declaration.

        :param ignore_binary_name:  Do not rely on the executable or library where the function belongs to determine
                                    its source library. This is useful when working on statically linked binaries
                                    (because all functions will belong to the main executable). We will search for all
                                    libraries in angr to find the first declaration match.
        :param binary_name_hint:    Substring of the library name where this function might be originally coming from.
                                    Useful for FLIRT-identified functions in statically linked binaries.
        :return:                    True if a declaration is found and self.prototype and self.calling_convention are
                                    updated. False if we fail to find a matching function declaration, in which case
                                    self.prototype or self.calling_convention will be kept untouched.
        """

        libraries: set[SimLibrary]

        if not ignore_binary_name:
            # determine the library name
            if not self.is_plt:
                binary_name = self.binary_name
                if binary_name not in SIM_LIBRARIES:
                    return False
            else:
                binary_name = None
                # PLT entries must have the same declaration as their jump targets
                # Try to determine which library this PLT entry will jump to
                edges = self.transition_graph.edges()
                if len(edges) == 0:
                    return False
                node = next(iter(edges))[1]
                if len(edges) == 1 and isinstance(node, (FuncNode, HookNode, SyscallNode)):
                    target = node.addr
                    if self._function_manager is not None and self._function_manager.contains_addr(target):
                        target_func = self._function_manager.get_by_addr(target)
                        binary_name = target_func.binary_name

            # cannot determine the binary name. since we are forced to respect binary name, we give up in this case.
            if binary_name is None:
                return False

            lib = SIM_LIBRARIES.get(binary_name, None)
            libraries = set()
            if lib is not None:
                libraries.update(lib)

        else:
            # try all libraries or all libraries that match the given library name hint
            libraries = set()
            for lib_name, libs in SIM_LIBRARIES.items():
                # TODO: Add support for syscall libraries. Note that syscall libraries have different function
                #  prototypes for .has_prototype() and .get_prototype()...
                for lib in libs:
                    if not isinstance(lib, SimSyscallLibrary):
                        if binary_name_hint:
                            if binary_name_hint.lower() in lib_name.lower():
                                libraries.add(lib)
                        else:
                            libraries.add(lib)

        if not libraries:
            return False

        name_variants = [self.name]
        # remove "_" prefixes
        if self.name.startswith("_"):
            name_variants.append(self.name[1:])
        if self.name.startswith("__"):
            name_variants.append(self.name[2:])
        # special handling for libc
        if self.name.startswith("__libc_"):
            name_variants.append(self.name[7:])

        for library in libraries:
            for name in name_variants:
                if isinstance(library, SimSyscallLibrary):
                    # FIXME: we don't support getting declaration from a syscall library yet. we don't have the concept
                    # of abi at this point.
                    continue
                if not library.has_prototype(name):
                    continue

                proto = library.get_prototype(name)
                if self.project is None:
                    # we need to get arch from self.project
                    l.warning(
                        "Function %s does not have .project set. A possible prototype is found, but we cannot set it "
                        "without .project.arch.",
                        self.name,
                    )
                    return False
                self.prototype = proto.with_arch(self.project.arch) if proto is not None else proto
                self.prototype_libname = library.name
                self.returning = library.is_returning(name)

                # update self.calling_convention if necessary
                if self.calling_convention is None:
                    if self.project.arch.name in library.default_ccs and self.is_syscall is False:
                        self.calling_convention = library.default_ccs[self.project.arch.name](self.project.arch)
                    elif self.project.arch.name in DEFAULT_CC:
                        cc_cls = default_cc_for_project(self.project, syscall=self.is_syscall is True)
                        if cc_cls is not None:
                            self.calling_convention = cc_cls(self.project.arch)

                return True

        return False

    @staticmethod
    def _addr_to_funcloc(addr):
        return addr

    def is_rust_function(self):
        """
        Determines if the function name follows Rust mangling conventions.
        """
        name = self.name

        # 1. Check for Rust v0 mangling (Newer standard, e.g., _RNvCs...)
        # Starts with _R followed by alphanumeric/underscores
        if name.startswith("_R"):
            return True

        # 2. Check for Legacy/Itanium mangling (Standard, e.g., _ZN3std2io...)
        # Rust legacy symbols almost always start with _ZN
        if name.startswith("_ZN"):
            # To distinguish from C++, look for the specific Rust hash pattern at the end.
            # Rust legacy symbols typically end with 'h' followed by 16 hex characters.
            # Example: _ZN3std2io5stdio6_print17h560ab85309735912E
            rust_hash_pattern = re.compile(r"h[0-9a-fA-F]{16}E?$")
            if rust_hash_pattern.search(name):
                return True

            # Fallback: If no hash is found, it *might* still be Rust (unhashed symbols),
            # but _ZN is shared with C++.
            # You might optionally check for common Rust crates in the name here.

        return False

    @staticmethod
    def _rust_fmt_node(node):
        result = []
        rest = node
        if rest.startswith("_$"):
            rest = rest[1:]
        while True:
            if rest.startswith("."):
                if len(rest) > 1 and rest[1] == ".":
                    result.append("::")
                    rest = rest[2:]
                else:
                    result.append(".")
                    rest = rest[1:]
            elif rest.startswith("$"):
                if "$" in rest[1:]:
                    escape, rest = rest[1:].split("$", 1)
                else:
                    break

                unescaped = {"SP": "@", "BP": "*", "RF": "&", "LT": "<", "GT": ">", "LP": "(", "RP": ")", "C": ","}.get(
                    escape
                )

                if unescaped is None and escape.startswith("u"):
                    digits = escape[1:]
                    if all(c in "0123456789abcdef" for c in digits):
                        c = chr(int(digits, 16))
                        if ord(c) >= 32 and ord(c) != 127:
                            result.append(c)
                            continue
                if unescaped:
                    result.append(unescaped)
                else:
                    break
            else:
                idx = min((rest.find(c) for c in "$." if c in rest), default=len(rest))
                result.append(rest[:idx])
                rest = rest[idx:]
                if not rest:
                    break
        return "".join(result)

    @property
    def demangled_name(self):
        if self.is_rust_function():
            return demangle(self.name)
        ast = pydemumble.demangle(self.name).strip()
        return ast or self.name

    @property
    def short_name(self):
        if self.is_rust_function():
            ast = pydemumble.demangle(self.name)
            return Function._rust_fmt_node(ast.split("::")[-2])
        func_name, meta = get_cpp_function_name_and_metadata(self.demangled_name)
        if meta["ctor"]:
            return "<ctor>"
        if meta["dtor"]:
            return "<dtor>"
        if "<" in func_name and ">" in func_name:
            # remove template arguments
            depth = 0
            new_name_chars = []
            suffix = ""
            if func_name.endswith(("<<", ">>")):
                suffix = func_name[-2:]
                func_name = func_name[:-2]
            for c in func_name:
                if c == "<":
                    depth += 1
                elif c == ">":
                    depth -= 1
                else:
                    if depth == 0:
                        new_name_chars.append(c)
            func_name = "".join(new_name_chars) + suffix
        return func_name.split("::")[-1] if "::" in func_name else func_name

    def get_unambiguous_name(self, display_name: str | None = None) -> str:
        """
        Get a disambiguated function name.

        :param display_name: Name to display, otherwise the function name.
        :return: The function name in one of the following forms:

            - ``::<name>`` when the function binary is the main object.
            - ``::<obj>::<name>`` when the function binary is not the main object.
            - ``::<addr>::<name>`` when the function binary is an unnamed non-main object, or when multiple functions
              with the same name are defined in the function binary.
        """
        assert self.project is not None
        must_disambiguate_by_addr = self.binary is not self.project.loader.main_object and self.binary_name is None

        # If there are multiple functions with the same name in the same object, disambiguate by address
        if not must_disambiguate_by_addr and self._function_manager is not None:
            for func in self._function_manager.get_by_name(self.name):
                if func is not self and func.binary is self.binary:
                    must_disambiguate_by_addr = True
                    break

        separator = "::"
        n = separator
        if must_disambiguate_by_addr:
            n += hex(self.addr) + separator
        elif self.binary is not self.project.loader.main_object and self.binary_name is not None:
            n += self.binary_name + separator
        return n + (display_name or self.name)

    def apply_definition(self, definition: str, calling_convention: SimCC | type[SimCC] | None = None) -> None:
        assert self.project is not None
        if not definition.endswith(";"):
            definition += ";"
        func_def = parse_defns(definition, arch=self.project.arch)
        if len(func_def.keys()) > 1:
            raise AngrValueError(f"Too many definitions: {list(func_def.keys())} ")

        name, ty = func_def.popitem()
        assert isinstance(ty, SimTypeFunction)
        self.name = name
        self.prototype = ty.with_arch(self.project.arch)
        # setup the calling convention
        # If a SimCC object is passed assume that this is sane and just use it
        if isinstance(calling_convention, SimCC):
            self.calling_convention = calling_convention

        # If it is a subclass of SimCC we can instantiate it
        elif isinstance(calling_convention, type) and issubclass(calling_convention, SimCC):
            self.calling_convention = calling_convention(self.project.arch)

        # If none is specified default to something
        elif calling_convention is None:
            self.calling_convention = self.project.factory.cc()

        else:
            raise TypeError("calling_convention has to be one of: [SimCC, type(SimCC), None]")

    def functions_reachable(self) -> set[Function]:
        """
        :return: The set of all functions that can be reached from the function represented by self.
        """
        if self._function_manager is None:
            return set()

        seen: set[int] = set()
        called: set[Function] = set()

        def _find_called(function_address):
            assert self._function_manager is not None
            for s in self._function_manager.callgraph.successors(function_address):
                if s in seen:
                    continue
                seen.add(s)
                func = self._function_manager.function(s)
                assert func is not None
                called.add(func)
                _find_called(s)

        _find_called(self.addr)
        return called

    def holes(self, min_size: int = 8) -> int:
        """
        Find the number of non-consecutive areas in the function that are at least `min_size` bytes large.
        """

        block_addrs = sorted(self._graph.local_addrs())
        if not block_addrs:
            return 0
        holes = 0
        for i, addr in enumerate(block_addrs):
            if i == len(block_addrs) - 1:
                break
            next_addr = block_addrs[i + 1]
            size = self._graph.block_size(addr)
            assert size is not None
            if next_addr > addr + size and next_addr - (addr + size) >= min_size:
                holes += 1
        return holes

    def copy(self):
        func = Function(self._function_manager, self.addr, name=self.name, syscall=self.is_syscall)
        func._graph = self._graph.copy()
        func.normalized = self.normalized
        func._project = self._project
        func.previous_names = list(self.previous_names)
        func._is_plt = self.is_plt
        func._is_simprocedure = self.is_simprocedure
        func.binary_name = self.binary_name
        func.bp_on_stack = self.bp_on_stack
        func.retaddr_on_stack = self.retaddr_on_stack
        func.sp_delta = self.sp_delta
        func._calling_convention = self.calling_convention
        func.prototype = self.prototype
        func._returning = self._returning
        func._is_alignment = self.is_alignment
        func._info = self.info.copy(func)
        func.tags = self.tags
        func._dirty = self._dirty

        return func

    def pp(self, **kwargs):
        """
        Pretty-print the function disassembly.
        """
        assert self.project is not None
        print(self.project.analyses.Disassembly(self).render(**kwargs))
