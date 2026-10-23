from collections.abc import Callable
from typing import Any

from .cfg_graph import CfgGraph

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
    ) -> None: ...
    def next_head(self, graph: CfgGraph, functions: Any) -> tuple[int, int] | None:
        """
        The next function head that is not a PLT stub, hook or syscall and has no incoming call edge: (addr, node id).
        `functions` is a RecoveryFunctions store or any container of function addresses.
        """

    def append_keys(self, keys: list[BlockKey]) -> None:
        """Add the keys of the nodes created during the first walk."""

    def next_overlap(self) -> tuple[BlockKey, BlockKey] | None:
        """The next pair of overlapping blocks (a, b); call resolve() before asking for the next one."""

    def resolve(self, b_removed: bool) -> None:
        """b was removed (a stays the current block), or a moves on to b."""
