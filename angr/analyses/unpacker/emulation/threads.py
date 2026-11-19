from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Thread:
    """
    An emulated thread: its own stack and TEB, plus the saved register file while it is not running.
    """

    tid: int
    teb: int
    stack_base: int
    start: int = 0
    param: int = 0
    registers: object = None
    started: bool = True
    alive: bool = True
    tls_slots: list[int] = field(default_factory=lambda: [0])
    waits: int = 0


@dataclass
class EventObject:
    """
    A Win32 event.
    """

    manual: bool
    signaled: bool
