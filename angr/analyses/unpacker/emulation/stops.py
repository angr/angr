from __future__ import annotations

import enum
from dataclasses import dataclass


class StopReason(enum.Enum):
    """
    Why WindowsEmulator.run() returned.
    """

    BUDGET = "budget"
    EXITED = "exited"
    RETURNED = "returned"
    EXEC_TRAP = "exec_trap"
    ERROR = "error"


@dataclass
class EmulationStop:
    """
    The result of one WindowsEmulator.run() call.
    """

    reason: StopReason
    addr: int
    detail: str = ""
