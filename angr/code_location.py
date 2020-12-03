from typing import Optional, Dict, Tuple


class CodeLocation:
    """
    Stands for a specific program point by specifying basic block address and statement ID (for IRSBs), or SimProcedure
    name (for SimProcedures).
    """

    __slots__ = ('block_addr', 'stmt_idx', 'sim_procedure', 'ins_addr', 'context', 'info', )

    def __init__(self, block_addr: int, stmt_idx: int, sim_procedure=None, ins_addr: Optional[int]=None,
                 context: Optional[Tuple]=None, **kwargs):
        """
        Constructor.

        :param block_addr:          Address of the block
        :param stmt_idx:            Statement ID. None for SimProcedures
        :param class sim_procedure: The corresponding SimProcedure class.
        :param ins_addr:            The instruction address.
        :param context:             A tuple that represents the context of this CodeLocation.
        :param kwargs:              Optional arguments, will be stored, but not used in __eq__ or __hash__.
        """

        self.block_addr: int = block_addr
        self.stmt_idx: int = stmt_idx
        self.sim_procedure = sim_procedure
        self.ins_addr: Optional[int] = ins_addr
        # sanitization: if context is an empty tuple, we store a None instead
        self.context: Optional[Tuple] = None if not context else context

        self.info: Optional[Dict] = None

        self._store_kwargs(**kwargs)

    def __repr__(self):
        if self.block_addr is None:
            return '<%s>' % self.sim_procedure

        else:
            if self.stmt_idx is None:
                s = "<%s%#x(-)" % (
                    ("%#x " % self.ins_addr) if self.ins_addr else "",
                    self.block_addr,
                )
            else:
                s = "<%s%#x[%d]" % (
                    ("%#x id=" % self.ins_addr) if self.ins_addr else "",
                    self.block_addr,
                    self.stmt_idx,
                )

            ss = [ ]
            if self.info:
                for k, v in self.info.items():
                    if v != tuple() and v is not None:
                        ss.append("%s=%s" % (k, v))
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
        return type(self) is type(other) and self.block_addr == other.block_addr and \
                self.stmt_idx == other.stmt_idx and self.sim_procedure is other.sim_procedure and \
                self.context == other.context

    def __hash__(self):
        """
        returns the hash value of self.
        """
        return hash((self.block_addr, self.stmt_idx, self.sim_procedure, self.context))

    def _store_kwargs(self, **kwargs):
        if self.info is None:
            self.info = { }
        for k, v in kwargs.items():
            self.info[k] = v
