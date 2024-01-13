from typing import Dict, Tuple

from angr.utils.constants import STATE_VARIABLE_BASE_OFFSET


class VariableCreator:
    """
    Creates and manages state variables during structuring.
    """

    __slots__ = (
        "base_offset",
        "next_offset",
        "next_id",
        "variables",
    )

    def __init__(self):
        self.base_offset = STATE_VARIABLE_BASE_OFFSET
        self.next_offset = self.base_offset
        self.next_id = 0
        self.variables: Dict[int, int] = {}  # offset to variable ID

    def next_variable(self, size: int = 8) -> Tuple[int, int]:
        off = self.next_offset
        idx = self.next_id

        self.next_offset += size
        self.next_id += 1

        self.variables[off] = idx

        return off, idx
