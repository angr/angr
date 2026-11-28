#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.statement import Label
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _block(addr: int, idx: int | None) -> Block:
    return Block(addr, 0, statements=[Label(0, f"LABEL_{addr:x}", ins_addr=addr, block_idx=idx)], idx=idx)


class TestOptimizationPassBfsNodes(unittest.TestCase):
    """
    bfs_nodes() sorts a node's successors by (addr, idx). A block that came out of graph recovery
    has idx None and a copy that a duplicating pass made has an int, so one address can hold both:
    the function this was measured on had four blocks at one address, with idx None, 1, 2 and 3.
    """

    @staticmethod
    def _optimization_pass(graph: networkx.DiGraph, entry: Block) -> OptimizationPass:
        # bfs_nodes reads the function's address and the two block indexes; a real project and a
        # real Function are cheap here because no CFG is needed to make one.
        project = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        func = project.kb.functions.function(addr=entry.addr, create=True)
        blocks_by_addr: dict[int, set[Block]] = {}
        blocks_by_addr_and_idx: dict[tuple[int, int | None], Block] = {}
        for block in graph:
            blocks_by_addr.setdefault(block.addr, set()).add(block)
            blocks_by_addr_and_idx[(block.addr, block.idx)] = block
        return OptimizationPass(
            func,
            Manager(),
            graph=graph,
            blocks_by_addr=blocks_by_addr,
            blocks_by_addr_and_idx=blocks_by_addr_and_idx,
        )

    def test_successors_at_one_address_mix_a_none_index_with_int_ones(self):
        entry = _block(0x400100, None)
        original = _block(0x400110, None)
        copies = [_block(0x400110, idx) for idx in (1, 2, 3)]
        graph = networkx.DiGraph()
        for successor in [original, *copies]:
            graph.add_edge(entry, successor)

        walked = list(self._optimization_pass(graph, entry).bfs_nodes(depth=5))

        # every node is reached, and the block that recovery produced comes before its copies
        assert walked == [entry, original, *copies]

    def test_two_int_indexes_at_one_address_still_sort_by_index(self):
        # the pair the old key compared without raising: both indexes set, so it ordered them and
        # went on. The new key has to leave that order alone, which is what says the change is
        # confined to the comparisons that used to raise.
        entry = _block(0x400100, None)
        second = _block(0x400110, 2)
        first = _block(0x400110, 1)
        graph = networkx.DiGraph()
        graph.add_edge(entry, second)
        graph.add_edge(entry, first)

        walked = list(self._optimization_pass(graph, entry).bfs_nodes(depth=5))

        assert walked == [entry, first, second]


if __name__ == "__main__":
    unittest.main()
