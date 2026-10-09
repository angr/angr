from __future__ import annotations

from angr.procedures import SIM_LIBRARIES as L

from .userland import SimUserland


class SimFreeBSD(SimUserland):
    """
    OS-specific configuration for FreeBSD.

    FreeBSD is not Linux at the syscall boundary: above the handful of numbers both
    systems inherited from Research Unix it numbers its syscalls differently, and on i386
    it takes their arguments from the stack rather than from registers.
    """

    def __init__(self, project, **kwargs):
        super().__init__(
            project,
            syscall_library=L["freebsd"][0],
            syscall_addr_alignment=project.arch.instruction_alignment,
            name="FreeBSD",
            **kwargs,
        )

    def configure_project(self, abi_list=None):
        # One ABI for every architecture: FreeBSD's native syscall numbers do not vary.
        super().configure_project(abi_list if abi_list is not None else ["freebsd"])

    def syscall_abi(self, state) -> str:
        return "freebsd"
