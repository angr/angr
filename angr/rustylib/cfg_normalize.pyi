from collections.abc import Callable

from .cfg_graph import CfgGraph

def normalize_cfg_graph(
    graph: CfgGraph, detach: Callable[[int], None], is_arm: bool
) -> tuple[list[tuple[int, tuple[int, int]]], list[int], list[tuple[int, list[int]]], list[tuple[int, int, int]]]:
    """
    CFGBase.normalize() on a CfgGraph. detach(id) is called before a record is removed or overwritten. Returns the
    updates of the side tables, in order: _blockid_to_blockkey assignments, addresses to drop from
    _block_addrs_with_return, (smallest node address, other node addresses) of every split group, and warnings
    (kind, addr_a, addr_b).
    """
