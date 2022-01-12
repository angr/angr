from typing import List, Dict


class SimActLocation:
    """
    Structure-like class used to bundle the instruction address and statement index of a given SimAction in order to
    uniquely identify a given SimAction
    """

    def __init__(self, ins_addr: int, stmt_idx: int, action_id: int):
        self._ins_addr = ins_addr
        self._stmt_idx = stmt_idx
        self._action_id = action_id

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

    @property
    def action_id(self) -> int:
        return self._action_id

    @action_id.setter
    def action_id(self, new_id: int):
        self._action_id = new_id

    def __repr__(self):
        return f"SimActLocation<{hex(self.ins_addr)}:{hex(self.stmt_idx)}(ID:{self.action_id})>"

    def __hash__(self):
        return hash(self.ins_addr) ^ hash(self.stmt_idx) ^ hash(self.action_id)

    def __eq__(self, other):
        if not isinstance(other, SimActLocation):
            return False

        return self.ins_addr == other.ins_addr and self.stmt_idx == other.stmt_idx and self.action_id == other.action_id

    def __add__(self, other):
        if not isinstance(other, int):
            return

        self._stmt_idx += other


DEFAULT_LOCATION = SimActLocation(0, 0, 0)  # To be used when a location isn't necessary (eg, ConstantDepNode)


class ParsedInstruction:
    """
    Used by parser to facilitate linking with recent ancestors in an efficient manner
    """

    def __init__(self, ins_addr: int,  # Instruction that was parsed
                 min_stmt_idx: int,  # Index of first statement in instruction
                 max_stmt_idx: int):  # Index of last statement in instruction
        self.ins_addr = ins_addr
        self.min_stmt_idx = min_stmt_idx
        self.max_stmt_idx = max_stmt_idx
        self._action_ids: List[int] = []  # SimAction IDs that pertain to this instruction

    @property
    def action_ids(self) -> List[int]:
        return self._action_ids

    @property
    def sorted_action_ids(self) -> List[int]:
        """
        Lazy getter
        Returns a reverse-sorted list of the action IDs
        """
        return sorted(self._action_ids, reverse=True)

    def add_action_id(self, id_: int):
        self._action_ids.append(id_)
