from __future__ import annotations

import logging
import weakref
from typing import TYPE_CHECKING

from archinfo.arch_soot import SootMethodDescriptor

import angr

if TYPE_CHECKING:
    from . import SimProcedure

l = logging.getLogger(name=__name__)


def repr_addr[K: (int, SootMethodDescriptor)](addr: K) -> str:
    if isinstance(addr, int):
        return hex(addr)
    return repr(addr)


class CodeNode[K: (int, SootMethodDescriptor)]:
    """
    The base class of nodes in a function graph.

    Graphless nodes are editable, but callers must not mutate their identity fields while keeping them in unrelated
    hash-based containers. Function graph ownership seals those fields permanently.
    """

    __slots__ = ["_graph", "_graph_ref", "_hash", "_semantic_identity_sealed", "addr", "size", "thumb"]

    _BASE_SEMANTIC_IDENTITY_FIELDS = frozenset(("addr", "size", "thumb"))
    _SUBCLASS_SEMANTIC_IDENTITY_FIELDS = frozenset(("func_name", "sim_procedure"))

    def __init__(self, addr: K, size: int, graph=None, thumb=False):
        if getattr(self, "_semantic_identity_sealed", False):
            raise ValueError("A graph-owned CodeNode cannot be reinitialized; copy and replace it instead")

        self._semantic_identity_sealed = False
        self.addr = addr
        self.size: int = size
        self.thumb = thumb
        self._graph = None
        self._graph_ref = None
        self._hash = None
        if graph is not None:
            self.set_graph(graph)

    @staticmethod
    def _is_safe_sealed_noop(old_value, new_value) -> bool:
        if old_value is new_value:
            return True
        return type(old_value) in (int, bool) and type(new_value) is type(old_value) and old_value == new_value

    def _is_sealed_semantic_identity_field(self, name: str) -> bool:
        if name in self._BASE_SEMANTIC_IDENTITY_FIELDS or name == "sim_procedure":
            return True
        if name == "func_name":
            try:
                return not self.is_addr_known
            except (AttributeError, TypeError):
                return True
        return False

    def __setattr__(self, name: str, value) -> None:
        if (
            getattr(self, "_semantic_identity_sealed", False)
            and self._is_sealed_semantic_identity_field(name)
            and hasattr(self, name)
        ):
            old_value = object.__getattribute__(self, name)
            if self._is_safe_sealed_noop(old_value, value):
                return
            raise ValueError(
                f"Cannot change CodeNode.{name} after graph ownership is established; copy and replace the node instead"
            )
        object.__setattr__(self, name, value)
        if (
            name in ("addr", "size")
            and not getattr(self, "_semantic_identity_sealed", False)
            and hasattr(self, "_hash")
        ):
            object.__setattr__(self, "_hash", None)

    def __delattr__(self, name: str) -> None:
        if name in self._BASE_SEMANTIC_IDENTITY_FIELDS | self._SUBCLASS_SEMANTIC_IDENTITY_FIELDS and hasattr(
            self, name
        ):
            raise ValueError(
                f"Cannot delete required CodeNode.{name}; assign a replacement value or copy and replace the node instead"
            )
        object.__delattr__(self, name)

    def __len__(self):
        return self.size

    def __eq__(self, other):
        if isinstance(other, angr.Block):
            raise TypeError("You do not want to be comparing a CodeNode to a Block")
        return (
            type(self) is type(other)
            and self.addr == other.addr
            and self.size == other.size
            and self.is_hook == other.is_hook
            and self.thumb == other.thumb
        )

    def __ne__(self, other):
        return not self == other

    def __cmp__(self, other):
        raise TypeError("Comparison with a code node")

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.addr, self.size))
        return self._hash

    def _capture_graph_binding_state(self) -> tuple:
        return self._graph, self._graph_ref, self._semantic_identity_sealed

    def _restore_graph_binding_state(self, state: tuple) -> None:
        graph, graph_ref, semantic_identity_sealed = state
        object.__setattr__(self, "_graph", graph)
        object.__setattr__(self, "_graph_ref", graph_ref)
        object.__setattr__(self, "_semantic_identity_sealed", semantic_identity_sealed)

    def _graph_owner(self):
        return self._graph_ref() if self._graph_ref is not None else None

    def set_graph(self, graph):
        if self._semantic_identity_sealed:
            owner = self._graph_owner()
            if owner is graph:
                return
            owner_description = "a collected graph" if owner is None else "another live graph"
            raise ValueError(
                f"A CodeNode owned by {owner_description} must be copied before insertion into a new graph"
            )

        graph_ref = weakref.ref(graph)
        graph_proxy = weakref.proxy(graph)
        object.__setattr__(self, "_graph", graph_proxy)
        object.__setattr__(self, "_graph_ref", graph_ref)
        object.__setattr__(self, "_semantic_identity_sealed", True)

    def successors(self) -> list[CodeNode]:
        if self._graph is None:
            raise ValueError("Cannot calculate successors for graphless node")
        return list(self._graph.successors(self))

    def predecessors(self):
        if self._graph is None:
            raise ValueError("Cannot calculate predecessors for graphless node")
        return list(self._graph.predecessors(self))

    def __getstate__(self) -> tuple:
        return self.addr, self.size

    def __setstate__(self, dat: tuple):
        self.__init__(*dat)

    is_hook = None


class BlockNode[K: (int, SootMethodDescriptor)](CodeNode[K]):
    """
    Represents a block of code in a function graph.
    """

    __slots__ = ["bytestr"]

    is_hook = False

    def __init__(self, addr: int, size, bytestr=None, **kwargs):
        super().__init__(addr, size, **kwargs)
        self.bytestr = bytestr

    def __repr__(self):
        return f"<BlockNode at {repr_addr(self.addr)} (size {self.size})>"

    def __getstate__(self) -> tuple:
        return self.addr, self.size, self.bytestr, self.thumb

    def __setstate__(self, dat: tuple):
        self.__init__(*dat[:-1], thumb=dat[-1])


class SootBlockNode(BlockNode[SootMethodDescriptor]):
    """
    Represents a Soot block of code in a function graph.
    """

    __slots__ = ["stmts"]

    def __init__(self, addr: SootMethodDescriptor, size, stmts, **kwargs):
        super().__init__(addr, size, **kwargs)
        self.stmts = stmts

        assert (stmts is None and size == 0) or (size == len(stmts))

    def __repr__(self):
        return f"<SootBlockNode at {repr_addr(self.addr)} ({self.size} statements)>"

    def __getstate__(self) -> tuple:
        return self.addr, self.size, self.stmts

    def __setstate__(self, data: tuple):
        self.__init__(*data)


class FuncNode[K: (int, SootMethodDescriptor)](CodeNode[K]):
    """
    Represents a function callee in a function graph.
    """

    __slots__ = ("func_name",)

    def __init__(self, addr: K, func_name: str | None = None, **kwargs):
        super().__init__(addr, 0, **kwargs)
        self.func_name = func_name  # only used when addr is -1 (unknown address)

    @property
    def is_addr_known(self) -> bool:
        return self.addr >= 0

    def __repr__(self) -> str:
        if self.func_name is not None:
            return f"<FuncNode {self.func_name}@{self.addr:#x}>"
        return f"<FuncNode {self.addr:#x}>"

    def __hash__(self):
        identity = (type(self), self.addr, self.size, self.is_hook, self.thumb)
        if not self.is_addr_known:
            identity += (self.func_name,)
        return hash(identity)

    def __eq__(self, other):
        return (
            isinstance(other, FuncNode)
            and super().__eq__(other)
            and (self.is_addr_known or (not self.is_addr_known and self.func_name == other.func_name))
        )

    def __getstate__(self) -> tuple:
        return self.addr, self.func_name, self.size, self.thumb

    def __setstate__(self, state: tuple):
        if not isinstance(state, tuple):
            raise TypeError(f"Invalid FuncNode pickle state type: {type(state).__name__}")
        if len(state) == 2:
            addr, func_name = state
            size, thumb = 0, False
        elif len(state) == 4:
            addr, func_name, size, thumb = state
        else:
            raise ValueError(f"Invalid FuncNode pickle state length: {len(state)}")
        self.__init__(addr, func_name, thumb=thumb)
        self.size = size


class HookNode[K: (int, SootMethodDescriptor)](CodeNode[K]):
    """
    Represents a hook in a function graph.
    """

    __slots__ = ["sim_procedure"]

    is_hook = True

    def __init__(self, addr, size, sim_procedure: SimProcedure | None, **kwargs):
        """
        :param type sim_procedure: the the sim_procedure class
        """
        super().__init__(addr, size, **kwargs)
        self.sim_procedure = sim_procedure

    def __repr__(self):
        return f"<HookNode {self.sim_procedure!r} at {repr_addr(self.addr)} (size {self.size})>"

    def __hash__(self):
        return hash((self.addr, self.size, self.sim_procedure.__class__))

    def __eq__(self, other: CodeNode):
        return (
            isinstance(other, HookNode)
            and super().__eq__(other)
            and (
                (self.sim_procedure is None and other.sim_procedure is None)
                or (
                    self.sim_procedure is not None
                    and other.sim_procedure is not None
                    and self.sim_procedure.__class__ == other.sim_procedure.__class__
                    and self.sim_procedure.display_name == other.sim_procedure.display_name
                )
            )
        )

    def __getstate__(self) -> tuple:
        return self.addr, self.size, self.sim_procedure

    def __setstate__(self, dat: tuple):
        self.__init__(*dat)


class SyscallNode[K: (int, SootMethodDescriptor)](HookNode[K]):
    """
    Represents a syscall in a function graph.
    """

    is_hook = False

    def __repr__(self):
        return f"<SyscallNode {self.sim_procedure!r} at {self.addr:#x} (size {self.size})>"
