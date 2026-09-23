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

    __slots__ = ["_hash", "_owner", "_project", "addr", "size", "thumb"]

    def __init__(self, addr: K, size: int, thumb=False):
        self.addr = addr
        self.size: int = size
        self.thumb = thumb
        # A weak reference to the Function whose transition graph this node belongs to; successors() and
        # predecessors() are answered by its graph store. It is weak because the Function keeps strong references to
        # its node objects: a strong back-reference would make every evicted Function a reference cycle that only
        # gen-2 GC could reclaim. The owner is not pickled (see __getstate__).
        self._owner: weakref.ref | None = None
        # The owner's Project, kept separately so that a node can still reach the loader after its Function has been
        # evicted from the function manager and collected.
        self._project: weakref.ref | None = None

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
        project = func.project
        self._project = None if project is None else weakref.ref(project)

    @property
    def owner(self):
        """
        The Function this node belongs to, or None if it was never registered with one or that Function is gone.
        """
        return None if self._owner is None else self._owner()

    @property
    def project(self):
        """
        The Project of the Function this node was registered with, or None. Unlike ``owner``, it stays available after
        the Function has been evicted and collected.
        """
        owner = self.owner
        if owner is not None and owner.project is not None:
            return owner.project
        return None if self._project is None else self._project()

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

    __slots__ = ["_bytestr", "delta", "manual"]

    is_hook = False

    def __init__(
        self,
        addr: int,
        size,
        bytestr: bytes | None = None,
        thumb: bool = False,
        manual: bool = False,
        delta: int | None = None,
    ):
        """
        :param manual:  The node was created by hand or programmatically rather than from lifted code. Only manual
                        nodes carry their own bytes; those are stored with the function graph. The bytes of every
                        other node are read from the loader on demand and never stored.
        :param delta:   The block's bytes live at ``addr + delta``. Defaults to -1 for Thumb nodes (their addr has
                        bit 0 set) and 0 otherwise. Not part of the node's identity.
        """
        super().__init__(addr, size, thumb=thumb)
        if bytestr is not None and not manual:
            raise TypeError("BlockNode bytes can only be given for a manual node (manual=True)")
        self.manual = manual
        self.delta = (-1 if thumb else 0) if delta is None else delta
        self._bytestr = bytestr

    @property
    def bytestr(self) -> bytes | None:
        """
        The bytes of the block: the stored bytes of a manual node, otherwise the raw loader bytes at
        ``addr + delta`` of the owning function's project (None when the node has no owner or the range is not
        fully mapped). ``kb.patches`` are deliberately not applied; use ``project.factory.block`` for patched code.
        """
        if self._bytestr is None and not self.manual:
            project = self.project
            if project is not None and self.size and isinstance(self.addr, int):
                loader = project.loader
                memory = loader.memory_ro_view if loader.memory_ro_view is not None else loader.memory
                try:
                    data = memory.load(self.addr + self.delta, self.size)
                except (KeyError, ValueError, SimMemoryError):
                    data = None
                if data is not None and len(data) == self.size:
                    self._bytestr = bytes(data)
        return self._bytestr

    @bytestr.setter
    def bytestr(self, v: bytes | None) -> None:
        if v is not None and not self.manual:
            raise TypeError("BlockNode bytes can only be set on a manual node (manual=True)")
        self._bytestr = v

    def __repr__(self):
        return f"<BlockNode at {repr_addr(self.addr)} (size {self.size})>"

    def __getstate__(self) -> tuple:
        return self.addr, self.size, self._bytestr if self.manual else None, self.thumb, self.manual, self.delta

    def __setstate__(self, dat: tuple):
        if len(dat) == 4:  # nodes pickled before manual/delta existed
            addr, size, _bytestr, thumb = dat
            self.__init__(addr, size, thumb=thumb)
            return
        addr, size, bytestr, thumb, manual, delta = dat
        self.__init__(addr, size, bytestr=bytestr, thumb=thumb, manual=manual, delta=delta)


class SootBlockNode(BlockNode[SootMethodDescriptor]):
    """
    Represents a Soot block of code in a function graph.
    """

    __slots__ = ["stmts"]

    def __init__(self, addr: SootMethodDescriptor, size, stmts, **kwargs):
        super().__init__(addr, size, manual=True, **kwargs)
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
