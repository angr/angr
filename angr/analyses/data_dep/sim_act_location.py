class SimActLocation:
    """
    Structure-like class used to bundle the instruction address and statement index of a given SimAction in order to
    uniquely identify a given SimAction
    """

    def __init__(self, bbl_addr: int, ins_addr: int, stmt_idx: int):
        self.bbl_addr = bbl_addr
        self.ins_addr = ins_addr
        self.stmt_idx = stmt_idx

    def __repr__(self):
        return f"SimActLocation<{hex(self.bbl_addr)}.{hex(self.ins_addr)}.{hex(self.stmt_idx)}>"

    def __hash__(self):
        return hash((self.bbl_addr, self.ins_addr, self.stmt_idx))

    def __eq__(self, other):
        if not isinstance(other, SimActLocation):
            return False
        return self.bbl_addr == other.bbl_addr and self.ins_addr == other.ins_addr and self.stmt_idx == other.stmt_idx

    # def __add__(self, other):
    #     if not isinstance(other, int):
    #         return
    #
    #     self._stmt_idx += other


DEFAULT_LOCATION = SimActLocation(0, 0, 0)  # To be used when a location isn't necessary (eg, ConstantDepNode)


class ParsedInstruction:
    """
    Used by parser to facilitate linking with recent ancestors in an efficient manner
    """

    def __init__(
        self,
        ins_addr: int,  # Instruction that was parsed
        min_stmt_idx: int,  # Index of first statement in instruction
        max_stmt_idx: int,
    ):  # Index of last statement in instruction
        self.ins_addr = ins_addr
        self.min_stmt_idx = min_stmt_idx
        self.max_stmt_idx = max_stmt_idx
