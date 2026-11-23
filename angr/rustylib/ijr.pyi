from collections.abc import Callable
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
        ctx: dict[str, Any],
        rust_precheck: bool,
        timeless: list[tuple[str | None, Any]],
        deferred: list[tuple[str | None, Any]],
        shadow: bool,
    ) -> None:
        """``ctx`` is built by ``angr.analyses.cfg.indirect_jump_resolvers.rust.build_chain``."""

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

    def resolve_pending(self, cfg: Any, release_gil: Callable[[int, int, float], None] | None = None) -> set[int]:
        """
        ``_process_unresolved_indirect_jumps``: resolve and write back every pending jump in address order;
        ``release_gil(idx, 50, 1e-6)`` is called before each one when given.
        """

    def finish(self, cfg: Any) -> None:
        """Publish Rust-owned resolver state (``kb.propagations`` FCP models)."""

    def debug_fcp(
        self, cfg: Any, func_addr: int, blocks: list[int] | None = None, cross_insn_opt: bool = False
    ) -> list[tuple[tuple[int, int, int], list[tuple[tuple[str, int, int], int]]]] | str:
        """FastConstantPropagation's replacements as rows, or the reason the Rust port declines."""

    def debug_blade(
        self,
        addr: int,
        dst_stmt_idx: int = -1,
        max_level: int = 3,
        stop_at_calls: bool = True,
        cross_insn_opt: bool = True,
        control_dependence: bool = False,
        ignore_sp: bool = False,
        ignore_bp: bool = False,
        ignored_regs: list[int] = ...,
        include_imarks: bool = True,
        max_predecessors: int = 10,
    ) -> tuple[list[tuple[int, int]], list[tuple[tuple[int, int], tuple[int, int]]]] | str:
        """A Blade slice's nodes and edges, or the reason the Rust port declines."""

    def stats(self) -> dict[str, int]: ...
    def mismatches(self) -> tuple[dict[str, Any], ...]: ...

class FcpTableView:
    """A published Rust FCP table; ``rows()`` gives ``((block_addr, stmt_idx, ins_addr), [(var, value)])``."""

    def rows(self) -> list[tuple[tuple[int, int, int], list[tuple[tuple[str, int, int], int]]]]: ...
    def __len__(self) -> int: ...

class CvmMapping:
    """``ConstantValueManager.mapping`` as a Rust FCP table."""

    def reg(self, block_addr: int, stmt_idx: int, ins_addr: int, offset: int, size: int) -> int | None:
        """``mapping[CodeLocation(block_addr, stmt_idx, ins_addr=ins_addr)][VEXReg(offset, size)]``, or None."""

    def rows(self) -> list[tuple[tuple[int, int, int], list[tuple[tuple[str, int, int], int]]]]: ...

class FcpService:
    """The Rust FCP that ConstantValueManager uses during a CFGFast run (separate from the resolver chain)."""

    shadow: bool

    def __init__(self, lifter: VexLifter, snapshot: LoaderSnapshot, ctx: dict[str, Any]) -> None: ...
    def cvm_mapping(self, cfg: Any, func_addr: int, ij_addr: int) -> CvmMapping | str:
        """``ConstantValueManager._build_mapping`` in Rust, or the reason the Python implementation must run."""

    def shadow_compare(self, func_addr: int, ij_addr: int, rust: CvmMapping, python: list) -> bool: ...
    def stats(self) -> dict[str, int]: ...
    def mismatches(self) -> tuple[dict[str, Any], ...]: ...
