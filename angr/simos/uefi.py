from __future__ import annotations

from .simos import SimOS


class SimUefi(SimOS):
    """
    Environment for UEFI images. UEFI is a boot-time environment with no process model and no syscall interface, so
    what distinguishes it from a bare SimOS is its calling conventions: the x86 bindings of the UEFI specification
    adopt the Microsoft conventions rather than the System V ones, which is what DEFAULT_CC records for "UEFI".
    """

    def __init__(self, project):
        super().__init__(project, name="UEFI")
