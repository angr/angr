from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from angr.protos import key_defs_pb2
from angr.serializable import Serializable


class CodeLocation[BlockAddr: int | None, StmtIdx: int | None, Context]:
    """
    Stands for a specific program point by specifying basic block address and statement ID (for IRSBs), or SimProcedure
    name (for SimProcedures).
    """

    __slots__ = (
        "_hash",
        "block_addr",
        "block_idx",
        "context",
        "info",
        "ins_addr",
        "sim_procedure",
        "stmt_idx",
    )

    def __init__(
        self,
        block_addr: BlockAddr,
        stmt_idx: StmtIdx,
        sim_procedure=None,
        ins_addr: int | None = None,
        context: Context = None,
        block_idx: int | None = None,
        **kwargs,
    ):
        """
        Constructor.

        :param block_addr:          Address of the block
        :param stmt_idx:            Statement ID. None for SimProcedures or if the code location is meant to refer to
                                    the entire block.
        :param class sim_procedure: The corresponding SimProcedure class.
        :param ins_addr:            The instruction address.
        :param context:             A tuple that represents the context of this CodeLocation in contextual mode, or
                                    None in contextless mode.
        :param kwargs:              Optional arguments, will be stored, but not used in __eq__ or __hash__.
        """

        self.block_addr = block_addr
        self.stmt_idx = stmt_idx
        self.sim_procedure = sim_procedure
        self.ins_addr = ins_addr
        self.context = context
        self.block_idx = block_idx
        self._hash = None

        self.info: dict[str, Any] | None = None

        if kwargs:
            self._store_kwargs(**kwargs)

    def __getstate__(self):
        # Exclude the cached hash from the pickle: it can fold in per-process-salted
        # hashes (e.g. of a SimProcedure class), so a persisted value is stale when
        # unpickled in another process. It is recomputed lazily instead.
        slotstate = {
            slot: getattr(self, slot)
            for klass in type(self).__mro__
            for slot in getattr(klass, "__slots__", ())
            if slot != "_hash" and hasattr(self, slot)
        }
        return getattr(self, "__dict__", None), slotstate

    def __setstate__(self, state):
        dictstate, slotstate = state if isinstance(state, tuple) else (None, state)
        if dictstate:
            self.__dict__.update(dictstate)
        for slot, value in (slotstate or {}).items():
            if slot != "_hash":
                setattr(self, slot, value)
        self._hash = None

    def __repr__(self):
        if self.block_addr is None:
            return f"<{self.sim_procedure}>"

        if self.stmt_idx is None:
            s = "<{}{:#x}(-)".format(
                (f"{self.ins_addr:#x} ") if self.ins_addr else "",
                self.block_addr,
            )
        else:
            s = f"<{(f'{self.ins_addr:#x} id=') if self.ins_addr else ''}{self.block_addr:#x}[{self.stmt_idx}]"

        if self.context is None:
            s += " contextless"
        else:
            s += f" context: {self.context!r}"

        ss = []
        if self.info:
            for k, v in self.info.items():
                if v != () and v is not None:
                    ss.append(f"{k}={v}")
            if ss:
                s += " with {}".format(", ".join(ss))
        s += ">"

        return s

    @property
    def short_repr(self):
        if self.ins_addr is not None:
            return f"{self.ins_addr:#x}"
        return repr(self)

    def __eq__(self, other):
        """
        Check if self is the same as other.
        """
        return (
            type(self) is type(other)
            and self.block_addr == other.block_addr
            and self.stmt_idx == other.stmt_idx
            and self.sim_procedure is other.sim_procedure
            and self.context == other.context
            and self.block_idx == other.block_idx
            and self.ins_addr == other.ins_addr
        )

    def __lt__(self, other):
        if self.block_addr != other.block_addr:
            if self.block_addr is None and other.block_addr is not None:
                return True
            if self.block_addr is not None and other.block_addr is None:
                return False
            # elif self.block_addr is not None and other.block_addr is not None:
            return self.block_addr < other.block_addr
        if self.stmt_idx != other.stmt_idx:
            if self.stmt_idx is None and other.stmt_idx is not None:
                return True
            if self.stmt_idx is not None and other.stmt_idx is None:
                return False
            # elif self.stmt_idx is not None and other.stmt_idx is not None
            return self.stmt_idx < other.stmt_idx
        if self.ins_addr is not None and other.ins_addr is not None and self.ins_addr != other.ins_addr:
            return self.ins_addr < other.ins_addr
        return False

    def __hash__(self):
        """
        returns the hash value of self.
        """
        if self._hash is None:
            self._hash = hash(
                (self.block_addr, self.stmt_idx, self.sim_procedure, self.ins_addr, self.context, self.block_idx)
            )
        return self._hash

    def _store_kwargs(self, **kwargs):
        if self.info is None:
            self.info = {}
        for k, v in kwargs.items():
            self.info[k] = v


class ExternalCodeLocation(CodeLocation):
    """
    Stands for a program point that originates from outside an analysis' scope.
    i.e. a value loaded from rdi in a callee where the caller has not been analyzed.
    """

    __slots__ = ("call_string",)

    def __init__(self, call_string: tuple[int, ...] | None = None):
        super().__init__(0, None)
        self.call_string = call_string if call_string is not None else ()

    def __repr__(self):
        return f"[External {[hex(x) if isinstance(x, int) else x for x in self.call_string]}]"

    def __hash__(self):
        """
        returns the hash value of self.
        """
        if self._hash is None:
            self._hash = hash((self.call_string,))
        return self._hash


@dataclass(frozen=True)
class AILCodeLocation(Serializable):
    """
    A code location that refers precisely to a statement of an AIL block, with an optional instruction address.
    """

    addr: int
    block_idx: int | None
    stmt_idx: int
    insn_addr: int | None = field(default=None, compare=False)

    @staticmethod
    def make_extern(idx: int):
        return AILCodeLocation(-1, None, idx)

    @classmethod
    def _get_cmsg(cls):
        return key_defs_pb2.AILCodeLocation()

    def serialize_to_cmessage(self):
        msg = key_defs_pb2.AILCodeLocation(addr=self.addr, stmt_idx=self.stmt_idx)
        if self.block_idx is not None:
            msg.block_idx = self.block_idx
        if self.insn_addr is not None:
            msg.insn_addr = self.insn_addr
        return msg

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        return cls(
            addr=cmsg.addr,
            block_idx=cmsg.block_idx if cmsg.HasField("block_idx") else None,
            stmt_idx=cmsg.stmt_idx,
            insn_addr=cmsg.insn_addr if cmsg.HasField("insn_addr") else None,
        )

    @property
    def insn_addr_unwrap(self) -> int:
        assert self.insn_addr is not None
        return self.insn_addr

    def __repr__(self):
        idx_expr = "" if self.block_idx is None else f".{self.block_idx}"
        return f"<Stmt {self.addr:#x}{idx_expr}[{self.stmt_idx}]>"

    @property
    def is_extern(self) -> bool:
        return self.addr == -1

    @property
    def extern_idx_unwrap(self) -> int:
        assert self.is_extern
        return self.stmt_idx

    @property
    def extern_idx(self) -> int | None:
        if self.is_extern:
            return self.stmt_idx
        return None

    @staticmethod
    def from_codeloc(codeloc: CodeLocation) -> AILCodeLocation:
        if isinstance(codeloc, ExternalCodeLocation):
            return AILCodeLocation(-1, -1, -1)
        assert codeloc.block_addr is not None
        assert codeloc.stmt_idx is not None
        return AILCodeLocation(codeloc.block_addr, codeloc.block_idx, codeloc.stmt_idx, codeloc.ins_addr)

    def __lt__(self, other: AILCodeLocation):
        if self.addr < other.addr:
            return True
        if self.addr > other.addr:
            return False
        if self.block_idx is None and other.block_idx is not None:
            return True
        if self.block_idx is not None and other.block_idx is None:
            return False
        if self.block_idx is not None and other.block_idx is not None and self.block_idx < other.block_idx:
            return True
        if self.block_idx is not None and other.block_idx is not None and self.block_idx > other.block_idx:
            return False
        if self.stmt_idx < other.stmt_idx:
            return True
        if self.stmt_idx > other.stmt_idx:
            return False
        return False

    @property
    def bbl_addr(self):
        # compat
        return self.addr

    @property
    def block_addr(self):
        # compat
        return self.addr

    @property
    def ins_addr(self):
        return self.insn_addr
