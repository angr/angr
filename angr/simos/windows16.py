from __future__ import annotations

from .simos import SimOS


class SimWindows16(SimOS):
    """Static-analysis environment for segmented 16-bit Windows programs.

    Win16 does not use the Win32 syscall or calling-convention model. This class deliberately supplies only generic
    project scaffolding until selector allocation, Win16 API thunks, and task-local runtime state are modeled.
    """

    def __init__(self, project):
        super().__init__(project, name="Win16")
