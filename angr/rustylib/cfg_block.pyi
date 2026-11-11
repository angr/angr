from collections.abc import Callable
from typing import Any

from .cfg_graph import CfgGraph
from .cfg_jobs import ScanState
from .cfg_scan import LinearSweep, LoaderSnapshot
from .recovery_functions import RecoveryFunctions
from .vexlift import VexLifter

class BlockScanner:
    """CFGFast's per-block scan in Rust; Python handles the jobs and successors it hands back."""

    def __init__(
        self,
        cfg: Any,
        scan: ScanState,
        graph: CfgGraph,
        store: RecoveryFunctions,
        lifter: VexLifter,
        snapshot: LoaderSnapshot,
        sweep: LinearSweep,
        resolver: Callable[[int], Any],
        syscall: tuple,
        exc_by_end: list[tuple[int, int | None]],
        memory_data_sorts: list[str],
        arch_registers: dict[str, tuple[int, int]],
        arm_options: tuple[bool, bool, bool] | None,
    ) -> None: ...
    def run(self, cfg: Any, budget_ns: int | None = None) -> bool:
        """
        Process queued jobs until the queue is empty or ``budget_ns`` has elapsed (False), or the front job needs
        Python (True; it is still queued and untouched).
        """
    def set_ijr(self, chain: Any, plt_all: bool, reverse_plt: list[int], indirect_jumps: dict[int, Any]) -> None:
        """
        Resolve indirect exits through the Rust resolver chain without escaping to ``_create_jobs`` where possible;
        ``plt_all``/``reverse_plt`` say where ``_resolve_plt`` would run.
        """

    def stats(self) -> dict[str, int]:
        """Counters of Rust-processed jobs and of escapes and callbacks by reason."""
