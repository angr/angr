#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.ailment import Block
from angr.ailment.expression import Const
from angr.ailment.manager import Manager
from angr.ailment.statement import Jump
from angr.analyses.decompiler.optimization_passes.optimization_pass import (
    OptimizationPass,
    OptimizationPassStage,
)


class _Probe(OptimizationPass):
    """A pass that does nothing, so that the base class's entry-block lookup can be exercised alone."""

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_AIL_GRAPH_CREATION
    NAME = "entry block lookup probe"
    DESCRIPTION = NAME

    def _check(self):
        return False, None

    def _analyze(self, cache=None):
        pass


class _Func:
    def __init__(self, addr):
        self.addr = addr


def _block(addr, target, idx=None):
    return Block(addr, 2, statements=[Jump(0, Const(1, target, 32), ins_addr=addr)], idx=idx)


def _probe(func_addr, entry_node_addr, blocks):
    graph = networkx.DiGraph()
    graph.add_nodes_from(blocks)
    by_addr: dict[int, set[Block]] = {}
    by_addr_and_idx = {}
    for b in blocks:
        by_addr.setdefault(b.addr, set()).add(b)
        by_addr_and_idx[(b.addr, b.idx)] = b
    return graph, _Probe(
        _Func(func_addr),
        Manager(),
        graph=graph,
        blocks_by_addr=by_addr,
        blocks_by_addr_and_idx=by_addr_and_idx,
        entry_node_addr=entry_node_addr,
    )


class TestEntryBlockIdentity(unittest.TestCase):
    """
    A pass may not identify the function's first block by address alone. Clinic duplicates an orphaned
    conditional jump to each of its predecessors before SSA, so the entry address can carry more than one
    AIL block, and Clinic also moves the entry when it drops a leading alignment block.
    """

    def test_entry_lookup_survives_a_duplicated_entry_block(self):
        entry = _block(0x400100, 0x400110)
        clone = _block(0x400100, 0x400110, idx=1)
        tail = _block(0x400110, 0x400100)
        graph, probe = _probe(0x400100, (0x400100, None), [entry, clone, tail])
        graph.add_edge(entry, tail)
        graph.add_edge(clone, tail)

        assert list(probe.bfs_nodes()) == [entry, tail]

    def test_entry_lookup_follows_an_entry_clinic_moved(self):
        # Clinic dropped a leading alignment block at the function address and recorded its successor as
        # the entry node, so nothing is left in the graph at the function address at all
        entry = _block(0x400110, 0x400120)
        tail = _block(0x400120, 0x400110)
        graph, probe = _probe(0x400100, (0x400110, None), [entry, tail])
        graph.add_edge(entry, tail)

        assert list(probe.bfs_nodes()) == [entry, tail]


if __name__ == "__main__":
    unittest.main()
