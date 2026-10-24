from typing import Any

from .cfg_scan import LoaderSnapshot
from .vexlift import VexLifter

class ResolverChain:
    """
    CFGFast's two resolver lists, each entry either a Rust resolver (with its Python instance as the twin it declines
    to) or the Python resolver itself, dispatched in list order with the Python loops' semantics.
    """

    def __init__(
        self,
        lifter: VexLifter,
        snapshot: LoaderSnapshot,
        sim_procedures: dict[int, Any],
        extra_stop_points: Any,
        exec_regions: list[tuple[int, int]],
        arch_bits: int,
        arch_bytes: int,
        strict_block_end: bool,
        default_opt_level: int,
        rust_precheck: bool,
        timeless: list[tuple[str | None, Any]],
        deferred: list[tuple[str | None, Any]],
        shadow: bool,
    ) -> None: ...
    def rust_kinds(self) -> tuple[list[str], list[str]]: ...
    def resolve_timeless(
        self,
        cfg: Any,
        addr: int,
        func_addr: int,
        block: Any,
        jumpkind: str,
        block_addr: int,
        block_size: int,
        block_nstmts: int,
    ) -> tuple[bool, Any]:
        """``_resolve_indirect_jump_timelessly``: the pre-check, then the timeless resolvers."""

    def resolve_deferred(self, cfg: Any, jump: Any, func_graph_complete: bool = True) -> tuple[bool, Any, Any, bool]:
        """``_process_one_indirect_jump``'s resolver loop: ``(resolved, resolved_by, targets, deferred)``."""

    def stats(self) -> dict[str, int]: ...
    def mismatches(self) -> tuple[dict[str, Any], ...]: ...
