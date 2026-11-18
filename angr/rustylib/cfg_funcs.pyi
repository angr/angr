from collections.abc import Callable
from typing import Any

from .cfg_graph import CfgGraph
from .cfg_scan import LoaderSnapshot
from .function_graph import FunctionGraph, NodeKind
from .recovery_functions import RecoveryFunctions

type BlockKey = tuple[int, int]
type NodeSpec = tuple[NodeKind, int, int, bool]

class FunctionsBuilder:
    """
    CFGBase.make_functions() in Rust: blockaddr_to_funcaddr, _addr_to_funcaddr, and the traversal of
    _graph_bfs_custom/_graph_traversal_handler with the FunctionManager._add_* calls it makes. The new functions are
    kept in a private RecoveryFunctions store until functions() hands them over. The builder is also the
    blockaddr_to_funcaddr mapping that the Python helpers of make_functions() read and write.
    """

    def __init__(
        self,
        graph: CfgGraph,
        known: RecoveryFunctions,
        hooks: dict[int, int],
        syscall_from: int | None,
        is_syscall_addr: Callable[[int], bool],
        new_function: Callable[[int], tuple[bool, bool, bool | None, str]],
        snippet: Callable[[int, int | None, bool, int], NodeSpec | None],
        snapshot: LoaderSnapshot | None,
        same_section: Callable[[int, int], bool],
        is_arm: bool,
        skip_unmapped_addrs: bool,
    ) -> None: ...
    def __contains__(self, addr: int) -> bool: ...
    def __getitem__(self, addr: int) -> int: ...
    def __setitem__(self, addr: int, func: int) -> None: ...
    def __delitem__(self, addr: int) -> None: ...
    def __len__(self) -> int: ...
    def get(self, addr: int, default: int | None = None) -> int | None: ...
    def addr_to_funcaddr(self, addr: int) -> int:
        """CFGBase._addr_to_funcaddr()"""

    def add_predetermined(self, addr: int) -> None:
        """One iteration of the loop over predetermined_function_addrs in make_functions()."""

    def traverse(
        self, starts: list[BlockKey], has_return: set[int], progress: Callable[[int], Any] | None = None
    ) -> None:
        """_graph_bfs_custom() from each start in turn; progress(i) is called before each start."""

    def secondary_starts(self) -> tuple[list[BlockKey], bool]:
        """The secondary start nodes, sorted by address, and whether two of them share an address."""

    def function_node_keys(self, removed: set[int]) -> list[BlockKey]:
        """Keys of the CFG nodes, in node order, whose address is a known function or in removed."""

    def empty_functions(self) -> list[int]:
        """Addresses of the new functions without a startpoint."""

    def traversed_keys(self) -> list[BlockKey]: ...
    def updated_nonreturning(self) -> list[int]: ...
    def tail_calls(self) -> list[int]: ...
    def functions(
        self,
    ) -> tuple[list[tuple[int, FunctionGraph, bool, bool, bool | None, bool | None]], list[tuple[int, dict[str, Any]]]]:
        """
        The new functions in creation order (addr, graph, is_syscall, is_simprocedure, is_plt or None, returning), and
        the info copies in the order they were made.
        """

    def fill_callgraph(self, callgraph: Any) -> None:
        """Fill an empty networkx MultiDiGraph with the callgraph."""

    def update_node_functions(self) -> None:
        """Set the function address of every CFG node whose address is mapped."""
