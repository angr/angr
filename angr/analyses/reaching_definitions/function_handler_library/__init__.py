from __future__ import annotations
from .stdlib import LibcStdlibHandlers, EnvironAtom, SystemAtom, ExecveAtom
from .stdio import LibcStdioHandlers, StdoutAtom, StdinAtom
from .unistd import LibcUnistdHandlers
from .string import LibcStringHandlers


class LibcHandlers(LibcStdlibHandlers, LibcStdioHandlers, LibcUnistdHandlers, LibcStringHandlers):
    pass


__all__ = ["EnvironAtom", "SystemAtom", "ExecveAtom", "StdoutAtom", "StdinAtom", "LibcHandlers"]
