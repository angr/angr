
class CodeLocation(object):
    """
    Stands for a specific program point by specifying basic block address and statement ID (for IRSBs), or SimProcedure
    name (for SimProcedures).
    """

    def __init__(self, simrun_addr, stmt_idx, sim_procedure=None, ins_addr=None, **kwargs):
        """
        Constructor.

        :param simrun_addr: Address of the SimRun
        :param stmt_idx: Statement ID. None for SimProcedures
        :param sim_procedure: The corresponding SimProcedure class.
        :param ins_addr: The instruction address. Optional.
        :param kwargs: Optional arguments, will be stored, but not used in __eq__ or __hash__.
        """

        self.simrun_addr = simrun_addr
        self.stmt_idx = stmt_idx
        self.sim_procedure = sim_procedure
        self.ins_addr = ins_addr

        self.info = { }

        self._store_kwargs(**kwargs)

    def __repr__(self):
        if self.simrun_addr is None:
            return '<%s>' % self.sim_procedure

        else:
            if self.stmt_idx is None:
                return "<%#x(-)%s>" % (self.simrun_addr, ("_%#x" % self.ins_addr) if self.ins_addr else "")
            else:
                return "<%#x(%d)%s>" % (
                    self.simrun_addr,
                    self.stmt_idx,
                    ("_%#x" % self.ins_addr) if self.ins_addr else ""
                )

    def __eq__(self, other):
        """
        Check if self is the same as other.
        """
        return self.simrun_addr == other.simrun_addr and self.stmt_idx == other.stmt_idx and \
               self.sim_procedure is other.sim_procedure

    def __hash__(self):
        """
        returns the hash value of self.
        """
        return hash((self.simrun_addr, self.stmt_idx, self.sim_procedure))

    def _store_kwargs(self, **kwargs):
        for k, v in kwargs:
            self.info[k] = v
