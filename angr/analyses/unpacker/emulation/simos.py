from __future__ import annotations

from angr.simos.windows import SimWindows


class SimWindowsEmulated(SimWindows):
    """
    SimWindows for WindowsEmulator: the emulator builds the process environment and dispatches exceptions itself.
    """

    def handle_exception(self, successors, engine, exception):
        raise exception
