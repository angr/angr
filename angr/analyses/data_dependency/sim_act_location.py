class SimActLocation:
    """
    Structure-like class used to bundle the instruction address and statement index of a given SimAction in order to
    uniquely identify a given SimAction
    """
    def __init__(self, ins_addr: int, stmt_idx: int):
        self._ins_addr = ins_addr
        self._stmt_idx = stmt_idx

    @property
    def ins_addr(self) -> int:
        return self._ins_addr

    @ins_addr.setter
    def ins_addr(self, new_ins_addr: int):
        self._ins_addr = new_ins_addr

    @property
    def stmt_idx(self) -> int:
        return self._stmt_idx

    @stmt_idx.setter
    def stmt_idx(self, new_stmt_idx: int):
        self._stmt_idx = new_stmt_idx

    def __repr__(self):
        return f"SimActLocation<{hex(self._ins_addr)},{hex(self._stmt_idx)}>"

    def __hash__(self):
        return hash(self._ins_addr) ^ hash(self._stmt_idx)

    def __eq__(self, other):
        if not isinstance(other, SimActLocation):
            return False

        return self._ins_addr == other.ins_addr and self.stmt_idx == other.stmt_idx

    def __add__(self, other):
        if not isinstance(other, int):
            return

        self._stmt_idx += other


DEFAULT_LOCATION = SimActLocation(0, 0)  # To be used when a location isn't necessary (eg, ConstantDepNode)
