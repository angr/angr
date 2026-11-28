from __future__ import annotations

import enum
from dataclasses import dataclass


class StopReason(enum.Enum):
    """
    The reason why `WindowsEmulator.run()` returned.
    """

    BUDGET = "budget"
    EXITED = "exited"
    RETURNED = "returned"
    EXEC_TRAP = "exec_trap"
    ERROR = "error"


@dataclass
class EmulationStop:
    """
    The result of one call of `WindowsEmulator.run()`.
    """

    reason: StopReason
    addr: int
    detail: str = ""
