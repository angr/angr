from typing import Optional, Dict, Tuple, Any


class CodeLocation:
    """
    Stands for a specific program point by specifying basic block address and statement ID (for IRSBs), or SimProcedure
    name (for SimProcedures).
    """

    __slots__ = (
        "block_addr",
        "stmt_idx",
        "sim_procedure",
        "ins_addr",
        "context",
        "info",
        "block_idx",
        "_hash",
    )

    def __init__(
        self,
        block_addr: int,
        stmt_idx: Optional[int],
        sim_procedure=None,
        ins_addr: Optional[int] = None,
        context: Any = None,
        block_idx: int = None,
        **kwargs,
    ):
        """
        Constructor.

        :param block_addr:          Address of the block
        :param stmt_idx:            Statement ID. None for SimProcedures or if the code location is meant to refer to
                                    the entire block.
        :param class sim_procedure: The corresponding SimProcedure class.
        :param ins_addr:            The instruction address.
        :param context:             A tuple that represents the context of this CodeLocation in contextful mode, or
                                    None in contextless mode.
        :param kwargs:              Optional arguments, will be stored, but not used in __eq__ or __hash__.
        """

        self.block_addr: int = block_addr
        self.stmt_idx: Optional[int] = stmt_idx
        self.sim_procedure = sim_procedure
        self.ins_addr: Optional[int] = ins_addr
        self.context: Optional[Tuple[int]] = context
        self.block_idx = block_idx
        self._hash = None

        self.info: Optional[Dict] = None

        if kwargs:
            self._store_kwargs(**kwargs)

    def __repr__(self):
        if self.block_addr is None:
            return "<%s>" % self.sim_procedure

        if self.stmt_idx is None:
            s = "<{}{:#x}(-)".format(
                ("%#x " % self.ins_addr) if self.ins_addr else "",
                self.block_addr,
            )
        else:
            s = "<%s%#x[%d]" % (
                ("%#x id=" % self.ins_addr) if self.ins_addr else "",
                self.block_addr,
                self.stmt_idx,
            )

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
                s += " with %s" % ", ".join(ss)
        s += ">"

        return s

    @property
    def short_repr(self):
        if self.ins_addr is not None:
            return "%#x" % self.ins_addr
        else:
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
            elif self.block_addr is not None and other.block_addr is None:
                return False
            # elif self.block_addr is not None and other.block_addr is not None:
            return self.block_addr < other.block_addr
        if self.stmt_idx != other.stmt_idx:
            if self.stmt_idx is None and other.stmt_idx is not None:
                return True
            elif self.stmt_idx is not None and other.stmt_idx is None:
                return False
            # elif self.stmt_idx is not None and other.stmt_idx is not None
            return self.stmt_idx < other.stmt_idx
        if self.ins_addr is not None and other.ins_addr is not None:
            if self.ins_addr != other.ins_addr:
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

    def __init__(self, call_string: Optional[Tuple[int, ...]] = None):
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
