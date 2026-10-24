from collections.abc import Callable, Iterator
from typing import Any

from .cfg_graph import CfgGraph
from .cfg_scan import LoaderSnapshot
from .recovery_functions import RecoveryFunctions

type FunctionReturnTuple = tuple[int | None, int, int, int | None]

class CFGJobType:
    """The kind of work a CFGJob does."""

    NORMAL: CFGJobType
    FUNCTION_PROLOGUE: CFGJobType
    COMPLETE_SCANNING: CFGJobType
    IFUNC_HINTS: CFGJobType
    DATAREF_HINTS: CFGJobType
    EH_FRAME_HINTS: CFGJobType
    @property
    def name(self) -> str: ...
    @property
    def value(self) -> int: ...

class FunctionTransitionEdge:
    """A transition edge in a function's transition graph, added when the job's block is scanned."""

    def __init__(
        self,
        src_node: Any,
        dst_addr: int,
        src_func_addr: int,
        to_outside: bool = False,
        dst_func_addr: int | None = None,
        stmt_idx: int | None = None,
        ins_addr: int | None = None,
        is_exception: bool = False,
    ) -> None: ...
    src_node: Any
    dst_addr: int
    src_func_addr: int
    to_outside: bool
    dst_func_addr: int | None
    stmt_idx: int | None
    ins_addr: int | None
    is_exception: bool
    def apply(self, cfg: Any) -> None: ...

class FunctionCallEdge:
    """A call edge in a function's transition graph."""

    def __init__(
        self,
        src_node: Any,
        dst_addr: int,
        ret_addr: int | None,
        src_func_addr: int,
        syscall: bool = False,
        stmt_idx: int | None = None,
        ins_addr: int | None = None,
    ) -> None: ...
    src_node: Any
    dst_addr: int
    ret_addr: int | None
    src_func_addr: int
    syscall: bool
    stmt_idx: int | None
    ins_addr: int | None
    def apply(self, cfg: Any) -> None: ...

class FunctionFakeRetEdge:
    """A FakeReturn (fall-through) edge in a function's transition graph."""

    def __init__(self, src_node: Any, dst_addr: int, src_func_addr: int, confirmed: bool | None = None) -> None: ...
    src_node: Any
    dst_addr: int
    src_func_addr: int
    confirmed: bool | None
    def apply(self, cfg: Any) -> None: ...

class FunctionReturnEdge:
    """A return edge (from a call or a syscall) in a function's transition graph."""

    def __init__(self, ret_from_addr: int, ret_to_addr: int, dst_func_addr: int) -> None: ...
    ret_from_addr: int
    ret_to_addr: int
    dst_func_addr: int
    def apply(self, cfg: Any) -> None: ...

type FunctionEdge = FunctionTransitionEdge | FunctionCallEdge | FunctionFakeRetEdge | FunctionReturnEdge

class CFGJob:
    """
    A CFGFast job. Jobs that come out of a ScanState are views over its records; their source node is resolved when
    they come out.
    """

    def __init__(
        self,
        addr: int,
        func_addr: int,
        jumpkind: str,
        ret_target: int | None = None,
        last_addr: int | None = None,
        src_node: Any = None,
        src_ins_addr: int | None = None,
        src_stmt_idx: int | None = None,
        returning_source: int | None = None,
        syscall: bool = False,
        func_edges: list[FunctionEdge] | None = None,
        job_type: CFGJobType = ...,
        gp: int | None = None,
    ) -> None: ...
    addr: int
    func_addr: int
    jumpkind: str
    ret_target: int | None
    last_addr: int | None
    src_node: Any
    src_ins_addr: int | None
    src_stmt_idx: int | None
    returning_source: int | None
    syscall: bool
    job_type: CFGJobType
    gp: int | None
    _func_edges: list[FunctionEdge] | None
    def add_function_edge(self, edge: FunctionEdge) -> None: ...
    def apply_function_edges(self, cfg: Any, clear: bool = False) -> None:
        """Add the function edges to the scan-time functions (in Rust while kb.functions is the scan's store)."""

class PendingJobs:
    """The pending return-site jobs of a ScanState, with the interface of cfg_fast.PyPendingJobs."""

    def __len__(self) -> int: ...
    def __bool__(self) -> bool: ...
    def add_job(self, job: CFGJob) -> None: ...
    def pop_job(self, returning: bool = True) -> CFGJob | None: ...
    def all_jobs(self) -> list[CFGJob]: ...
    def add_returning_function(self, func_addr: int | None) -> None: ...
    def add_nonreturning_function(self, func_addr: int | None) -> None: ...
    def clear_updated_functions(self) -> None: ...
    def updated_functions(self) -> list[int | None]:
        """The updated functions in the order a Python set would iterate them."""
    def cleanup(self) -> None:
        """Drop (and deregister) the pending jobs whose callee is now known not to return."""

class TracedAddresses:
    """The traced-address set of a ScanState."""

    def __contains__(self, addr: object) -> bool: ...
    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[int]: ...
    def add(self, addr: int) -> None: ...
    def update(self, addrs: list[int]) -> None: ...
    def discard(self, addr: int) -> None: ...

class CompletedFunctions:
    """The completed-function set of a ScanState."""

    def __contains__(self, addr: object) -> bool: ...
    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[int]: ...
    def add(self, addr: int) -> None: ...
    def discard(self, addr: int) -> None: ...

class ScanState:
    """
    The state of CFGFast's scan loop: the FIFO job queue, pending jobs, per-function job accounting, traced
    addresses and FunctionReturn records.
    """

    def __init__(self, resolver: Callable[[int], Any] | None = None) -> None: ...
    def bind(
        self,
        graph: CfgGraph,
        store: RecoveryFunctions,
        manager: Any,
        kb: Any,
        sim_procedures: dict[int, Any],
        errors: tuple[type[BaseException], ...],
    ) -> None: ...
    def push(self, job: CFGJob) -> None: ...
    def queue_len(self) -> int: ...
    def peek(self) -> CFGJob | None: ...
    def peek_at(self, pos: int) -> CFGJob: ...
    def pop_front(self, key_addr: int) -> None: ...
    def has_job_addr(self, addr: int) -> bool: ...
    def queued_jobs(self) -> list[CFGJob]: ...
    def remove_jobs_by_src_addr(self, addr: int) -> int: ...
    def remove_jobs_by_mask(self, mask: list[bool]) -> int: ...
    def orphan_node(self, id: int, node: Any) -> None: ...  # pylint:disable=redefined-builtin
    def register_job(self, func_addr: int, job: object) -> None: ...
    def deregister_job(self, func_addr: int, job: object) -> None: ...
    def finished_functions(self) -> list[int]: ...
    def cleanup_analysis_jobs(self, func_addrs: list[int]) -> None: ...
    def function_has_jobs(self, func_addr: int) -> bool: ...
    def take_completed(self, snapshot: LoaderSnapshot, filter: int) -> list[int] | None:
        """
        Mark the finished functions completed and clean up their jobs. Returns the newly completed ones whose
        _function_completed can have an effect (filter: 0 none, 1 AMD64, 2 X86), or None if kb.functions is not the
        store's manager.
        """
    def add_function_return(
        self, callee_func_addr: int | None, caller_func_addr: int, call_site_addr: int, return_to: int | None
    ) -> None: ...
    def has_function_returns(self, callee_func_addr: int | None) -> bool: ...
    def take_function_returns(self, callee_func_addr: int | None) -> list[FunctionReturnTuple] | None: ...
    @property
    def pending(self) -> PendingJobs: ...
    @property
    def traced(self) -> TracedAddresses: ...
    @property
    def completed(self) -> CompletedFunctions: ...

def set_iteration_order(hashes: list[int]) -> list[int]: ...
def function_return_hash_of(fr: FunctionReturnTuple) -> int: ...
