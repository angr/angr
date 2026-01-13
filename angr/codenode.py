from __future__ import annotations
from typing import TypeVar, TYPE_CHECKING
import logging
import weakref

from archinfo.arch_soot import SootMethodDescriptor

if TYPE_CHECKING:
    from . import SimProcedure

l = logging.getLogger(name=__name__)

K = TypeVar("K", int, SootMethodDescriptor)


def repr_addr(addr: K) -> str:
    if isinstance(addr, int):
        return hex(addr)
    return repr(addr)


class CodeNode:
    """
    The base class of nodes in a function graph.
    """

    __slots__ = ["_graph", "_hash", "addr", "size", "thumb"]

    def __init__(self, addr: K, size: int, graph=None, thumb=False):
        self.addr = addr
        self.size: int = size
        self.thumb = thumb
        self._graph = weakref.proxy(graph) if graph is not None else None

        self._hash = None

    def __len__(self):
        return self.size

    def __eq__(self, other):
        if type(other) is Block:  # pylint: disable=unidiomatic-typecheck
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

    def set_graph(self, graph):
        self._graph = weakref.proxy(graph)

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


class BlockNode(CodeNode):
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


class SootBlockNode(BlockNode):
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


class FuncNode(CodeNode):
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
        return hash((FuncNode, self.addr, self.func_name))

    def __eq__(self, other):
        return (
            isinstance(other, FuncNode)
            and super().__eq__(other)
            and (self.is_addr_known or (not self.is_addr_known and self.func_name == other.func_name))
        )

    def __getstate__(self) -> tuple:
        return self.addr, self.func_name

    def __setstate__(self, state: tuple):
        self.__init__(*state)


class HookNode(CodeNode):
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


class SyscallNode(HookNode):
    """
    Represents a syscall in a function graph.
    """

    is_hook = False

    def __repr__(self):
        return f"<SyscallNode {self.sim_procedure!r} at {self.addr:#x} (size {self.size})>"


from .block import Block
