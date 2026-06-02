from __future__ import annotations

from .stdio import LibcStdioHandlers, StdinAtom, StdoutAtom
from .stdlib import EnvironAtom, ExecveAtom, LibcStdlibHandlers, SystemAtom
from .string import LibcStringHandlers
from .unistd import LibcUnistdHandlers


class LibcHandlers(LibcStdlibHandlers, LibcStdioHandlers, LibcUnistdHandlers, LibcStringHandlers):
    pass


__all__ = ["EnvironAtom", "ExecveAtom", "LibcHandlers", "StdinAtom", "StdoutAtom", "SystemAtom"]
