from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Thread:
    """
    An emulated thread.

    Each thread has its own stack and TEB.
    We save the registers of a thread while the thread is not running.
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
    wake_tick: int = 0
    wait_handle: int | None = None
    # the wait on `wait_handle` ends at `wake_tick`
    timed_wait: bool = False
    # posted window messages: (hwnd, message, wParam, lParam)
    messages: list[tuple[int, int, int, int]] = field(default_factory=list)
    # the threads of the windows whose window procedures this thread is running, with the innermost one last
    window_owners: list[Thread] = field(default_factory=list)
    # NtSetInformationThread(ThreadHideFromDebugger) sets this flag
    hide_from_debugger: bool = False


@dataclass
class EventObject:
    """
    A Win32 event.
    """

    manual: bool
    signaled: bool
