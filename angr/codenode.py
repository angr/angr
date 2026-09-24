from __future__ import annotations

import logging
import weakref
from typing import TYPE_CHECKING

from archinfo.arch_soot import SootMethodDescriptor

import angr
from angr.errors import SimMemoryError

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
    """

    __slots__ = ["_hash", "_owner", "addr", "size", "thumb"]

    def __init__(self, addr: K, size: int, thumb=False):
        self.addr = addr
        self.size: int = size
        self.thumb = thumb
        # A weak reference to the Function whose transition graph this node belongs to; successors() and
        # predecessors() are answered by its graph store. It is weak because the Function keeps strong references to
        # its node objects: a strong back-reference would make every evicted Function a reference cycle that only
        # gen-2 GC could reclaim. The owner is not pickled (see __getstate__).
        self._owner: weakref.ref | None = None

        self._hash = None

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

    def set_owner(self, func) -> None:
        self._owner = weakref.ref(func)

    @property
    def owner(self):
        """
        The Function this node belongs to, or None if it was never registered with one or that Function is gone.
        """
        return None if self._owner is None else self._owner()

    def _require_owner(self):
        owner = self.owner
        if owner is None:
            raise ValueError(f"Cannot calculate successors or predecessors of {self!r}: it belongs to no function")
        return owner

    def successors(self) -> list[CodeNode]:
        return self._require_owner()._successors_of(self)

    def predecessors(self) -> list[CodeNode]:
        return self._require_owner()._predecessors_of(self)

    def __getstate__(self) -> tuple:
        return self.addr, self.size

    def __setstate__(self, dat: tuple):
        self.__init__(*dat)

    is_hook = None


class BlockNode[K: (int, SootMethodDescriptor)](CodeNode[K]):
    """
    Represents a block of code in a function graph.
    """

    __slots__ = ["_bytestr", "delta"]

    is_hook = False

    def __init__(
        self,
        addr: K,
        size: int,
        bytestr: bytes | None = None,
        thumb: bool = False,
        delta: int | None = None,
    ):
        """
        :param bytestr: The bytes of the block, given only when the bytes are from user-specified binary code.
        :param delta:   The block's bytes are at ``addr + delta``. Defaults to -1 for ARM Thumb nodes. Note that delta
                        is not part of the identity of a BlockNode.
        """
        super().__init__(addr, size, thumb=thumb)
        self.delta = (-1 if thumb else 0) if delta is None else delta
        self._bytestr = bytestr

    @property
    def manual_bytes(self) -> bool:
        """
        True if the node carries user-supplied bytes rather than reading them from the loader.
        """
        return self._bytestr is not None

    def bytestr(self, project: angr.Project) -> bytes | None:
        """
        Get the bytes of the block.
        """
        if self._bytestr is not None:
            return self._bytestr
        if not isinstance(project, angr.Project):
            raise TypeError(f"BlockNode.bytestr() expects a Project, not {type(project).__name__}")
        if not self.size or not isinstance(self.addr, int):
            return None
        loader = project.loader
        memory = loader.memory_ro_view if loader.memory_ro_view is not None else loader.memory
        try:
            data = memory.load(self.addr + self.delta, self.size)
        except (KeyError, ValueError, SimMemoryError):
            return None
        if data is None or len(data) != self.size:
            return None
        return bytes(data)

    def __repr__(self):
        return f"<BlockNode at {repr_addr(self.addr)} (size {self.size})>"

    def __getstate__(self) -> tuple:
        return self.addr, self.size, self._bytestr, self.thumb, self.delta

    def __setstate__(self, dat: tuple):
        if len(dat) == 4:  # nodes pickled before delta existed: (addr, size, bytestr, thumb); bytes were loader bytes
            addr, size, _bytestr, thumb = dat
            self.__init__(addr, size, thumb=thumb)
        elif len(dat) == 6:  # (addr, size, bytestr, thumb, manual, delta)
            addr, size, bytestr, thumb, manual, delta = dat
            self.__init__(addr, size, bytestr=bytestr if manual else None, thumb=thumb, delta=delta)
        else:
            addr, size, bytestr, thumb, delta = dat
            self.__init__(addr, size, bytestr=bytestr, thumb=thumb, delta=delta)


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
