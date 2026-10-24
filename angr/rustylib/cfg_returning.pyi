from collections.abc import Callable
from typing import Any

from .cfg_jobs import ScanState
from .cfg_scan import LinearSweep
from .recovery_functions import RecoveryFunctions

class ReturningAnalyzer:
    """
    CFGBase._analyze_function_features and _determine_function_returning over a RecoveryFunctions store, for the
    scan-time calls of CFGFast.
    """

    def __init__(
        self,
        scan: ScanState,
        store: RecoveryFunctions,
        sweep: LinearSweep,
        sim_procedures: dict[int, Any],
        unresolvable_jump_target: type,
        syscall: tuple,
        syscall_returning: Callable[[int], bool | None],
    ) -> None:
        """
        :param syscall: How to tell which addresses syscall_from_addr can return a procedure for: ("never",),
                        ("userland", kernel_base, align, max_number), ("dict", handlers), ("callback",
                        is_syscall_addr) or ("always",).
        :param syscall_returning: `not NO_RET` of the syscall procedure at an address, or None.
        """

    def analyze(self, seeds: list[int], all_completed: bool) -> tuple[list[int], list[int]]:
        """
        One _analyze_function_features pass. Returning statuses are written to the store as they are determined.

        :return: (functions_return, functions_do_not_return)
        """
