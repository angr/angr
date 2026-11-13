#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.ailment import Block
from angr.ailment.expression import Const
from angr.ailment.statement import Jump
from angr.analyses.decompiler.optimization_passes.return_duplicator_base import ReturnDuplicatorBase
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.structurer_nodes import ConditionNode, MultiNode


def _block(addr):
    return Block(addr, 1, statements=[Jump(0, Const(0, addr + 1, 32), ins_addr=addr)])


class TestReturnDuplicatorRegionBlockSets(unittest.TestCase):
    """
    _find_block_sets_in_all_regions maps every region of the region tree to the addresses of the blocks inside it.
    The tree can be deeper than Python's recursion limit: one 1340-block function in a 32-bit Windows PE produced a
    tree of 1897 regions, 1267 levels deep.
    """

    LEVELS = 2000

    def test_a_region_tree_deeper_than_the_recursion_limit(self):
        blocks = [_block(0x400000 + i * 0x10) for i in range(self.LEVELS + 1)]
        graph = networkx.DiGraph()
        networkx.add_path(graph, blocks)
        mgr = OverlayManager(graph)
        mgr.root.head = blocks[0]
        inner = blocks[-1]
        for block in reversed(blocks[1:-1]):
            inner = mgr.root.create_subregion(block, [block, inner], cyclic=False)

        sets = ReturnDuplicatorBase._find_block_sets_in_all_regions(mgr.root)

        assert len(sets) == self.LEVELS
        for region, addrs in sets.items():
            assert addrs == {block.addr for block in region.underlying_nodes()}
        assert sets[mgr.root] == {block.addr for block in blocks}

    def test_multinodes_and_condition_nodes_contribute_the_blocks_inside_them(self):
        a, b, c, d, e, f = (_block(0x400000 + i * 0x10) for i in range(6))
        multi = MultiNode([a, b], addr=a.addr)
        cond = ConditionNode(c.addr, None, True, c, d)
        graph = networkx.DiGraph()
        networkx.add_path(graph, [multi, cond, e, f])
        mgr = OverlayManager(graph)
        mgr.root.head = multi
        sub = mgr.root.create_subregion(e, [e, f], cyclic=False)

        sets = ReturnDuplicatorBase._find_block_sets_in_all_regions(mgr.root)

        assert sets == {mgr.root: {a.addr, b.addr, c.addr, d.addr, e.addr, f.addr}, sub: {e.addr, f.addr}}


if __name__ == "__main__":
    unittest.main()
