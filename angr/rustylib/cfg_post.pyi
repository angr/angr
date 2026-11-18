from collections.abc import Callable
from typing import Any

from .cfg_graph import CfgGraph
from .cfg_scan import LoaderSnapshot
from .function_graph import FunctionGraph

type BlockKey = tuple[int, int]

class OverlapScan:
    """
    The two walks of CFGFast._remove_redundant_overlapping_blocks over the sorted node keys of a CfgGraph. Filters are
    evaluated against the graph when the walk reaches a key, so Python may mutate the graph between calls.
    """

    def __init__(
        self,
        graph: CfgGraph,
        hooked: set[int],
        plt_stubs: set[int],
        syscall_from: int | None,
        is_syscall_addr: Callable[[int], bool] | None,
        is_arm: bool,
        function_alignment: int = 16,
        x86_snapshot: LoaderSnapshot | None = None,
        x86_64: bool = False,
    ) -> None: ...
    def next_head(self, graph: CfgGraph, functions: Any) -> tuple[int, int] | None:
        """
        The next function head that is not a PLT stub, hook or syscall and has no incoming call edge: (addr, node id).
        `functions` is a RecoveryFunctions store or any container of function addresses.
        """

    def append_keys(self, keys: list[BlockKey]) -> None:
        """Add the keys of the nodes created during the first walk."""

    def next_overlap(self, graph: CfgGraph) -> tuple[BlockKey, BlockKey, bool | None] | None:
        """
        The next pair of overlapping blocks (a, b, big_nop) that needs Python; call resolve() before asking for the
        next one. big_nop tells whether the bytes between a and b are all nops (None: lift them to find out).
        """

    def resolve(self, b_removed: bool) -> None:
        """b was removed (a stays the current block), or a moves on to b."""

X86_NOPS: list[bytes]
"""The x86 nop encodings on which pyvex and capstone agree; the overlap pass classifies them without lifting."""

def x86_leading_nop_len(bytes: bytes, max_size: int, is_64: bool) -> int | None:
    """The nop length the overlap pass computes for a block of at most max_size bytes, if the bytes decide it."""

def x86_all_nops(bytes: bytes, is_64: bool) -> bool | None:
    """Whether capstone decodes the bytes into nothing but nops, if the bytes decide it."""

def x86_alignment_verdicts(
    snapshot: LoaderSnapshot, cfg_graph: CfgGraph, graphs: list[FunctionGraph], is_64: bool
) -> list[bool | None]:
    """
    The verdicts of CFGBase.mark_function_alignments() for single-block x86 functions, from the bytes, the
    CFG nodes and the function graphs: True (an alignment), False (not one), or None when only lifting can tell.
    """
