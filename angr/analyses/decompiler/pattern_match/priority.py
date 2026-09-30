"""Keeping the pattern analyses from starving other threads, a GUI's in particular."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

#: seconds between two yields
YIELD_INTERVAL = 0.02
#: how long a yield sleeps; a microsecond is too short for the OS to wake the GUI thread before
#: this one takes the GIL back
YIELD_SLEEP = 0.001


class Checkpoint:
    """Called from inside hot loops, as often as is convenient.

    Every ``freq`` calls it looks at the clock, and at most once per ``interval``
    seconds it sleeps for ``sleep`` seconds to let other threads take the GIL, as the
    CFG's low-priority mode does, and then runs ``callback``. The callback may raise to
    abort the analysis; a UI uses that to cancel.
    """

    __slots__ = ("_calls", "_last", "callback", "freq", "interval", "low_priority", "sleep")

    def __init__(
        self,
        low_priority: bool = True,
        callback: Callable[[], None] | None = None,
        freq: int = 1,
        interval: float = YIELD_INTERVAL,
        sleep: float = YIELD_SLEEP,
    ):
        self.low_priority = low_priority
        self.callback = callback
        self.freq = max(1, freq)
        self.interval = interval
        self.sleep = sleep
        self._calls = 0
        self._last = time.perf_counter()

    def __call__(self) -> None:
        self._calls += 1
        if self._calls % self.freq:
            return
        now = time.perf_counter()
        if now - self._last < self.interval:
            return
        if self.low_priority:
            time.sleep(self.sleep)
        self._last = time.perf_counter()
        if self.callback is not None:
            self.callback()
