#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import networkx

import angr
from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import Const
from angr.ailment.statement import Jump
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer
from angr.analyses.decompiler.utils import sequence_to_blocks
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class _Overlay:
    """Stands in for a region overlay graph: _last_resort_refinement() only calls filtered() on these."""

    def __init__(self, graph):
        self._graph = graph

    def filtered(self):
        return self._graph


class _Region:
    """Only the type-4 cycle fallback reads these, and that branch needs a cyclic graph."""

    parent = None
    cyclic = False


class TestPhoenixLastResortIsolation(unittest.TestCase):
    """
    Last-resort refinement buckets candidate edges by dominance, and immediate_dominators() only covers nodes
    reachable from the region head. For unreachable debris both dominance queries answer False, which is the
    first-choice bucket -- so an edge that is a node's only way in gets virtualized and the node is orphaned. No
    schema can reattach an isolated node, so the region never reduces.
    """

    @staticmethod
    def _block(m, addr):
        return Block(addr, 1, statements=[Jump(m.next_atom(), Const(m.next_atom(), addr + 1, 64), ins_addr=addr)])

    @staticmethod
    def _refine(graph, head):
        """Run the candidate selection, recording the edge it would virtualize instead of performing it."""
        structurer = object.__new__(PhoenixStructurer)
        structurer._improve_algorithm = False
        structurer._edge_virtualization_hints = []
        structurer.whitelist_edges = set()
        structurer._region = _Region()
        chosen = []

        def _virtualize_edge(src, dst):
            chosen.append((src, dst))
            return True

        structurer._virtualize_edge = _virtualize_edge
        overlay = _Overlay(graph)
        progressed = PhoenixStructurer._last_resort_refinement(structurer, head, overlay, overlay)
        return progressed, chosen

    def test_edge_that_would_orphan_its_destination_is_not_picked(self):
        m = Manager(arch=None)
        head = self._block(m, 0x100)
        # x -> y hangs off the region unreachable from head, and it is y's only way in
        x, y = self._block(m, 0x200), self._block(m, 0x300)
        graph = networkx.DiGraph()
        graph.add_node(head)
        graph.add_edge(x, y)

        progressed, chosen = self._refine(graph, head)

        # nothing left to virtualize; reporting no progress dissolves the region instead of orphaning y
        assert not progressed
        assert not chosen

    def test_a_safe_edge_is_still_picked(self):
        m = Manager(arch=None)
        head = self._block(m, 0x100)
        a, b = self._block(m, 0x200), self._block(m, 0x300)
        # b keeps a second way in, so cutting a -> b orphans nothing
        graph = networkx.DiGraph()
        graph.add_edge(head, a)
        graph.add_edge(head, b)
        graph.add_edge(a, b)

        progressed, chosen = self._refine(graph, head)

        assert progressed
        assert chosen == [(a, b)]

    def test_orphaning_edge_is_skipped_in_favour_of_a_safe_one(self):
        m = Manager(arch=None)
        head = self._block(m, 0x100)
        a, b = self._block(m, 0x200), self._block(m, 0x300)
        x, y = self._block(m, 0x400), self._block(m, 0x500)
        graph = networkx.DiGraph()
        graph.add_edge(head, a)
        graph.add_edge(head, b)
        graph.add_edge(a, b)
        graph.add_edge(x, y)

        progressed, chosen = self._refine(graph, head)

        assert progressed
        assert chosen == [(a, b)]

    def test_bbbq_rust_root_region_structures_completely(self):
        """
        sub_410920 is where this showed up: three edges were cut that each orphaned their destination, the region
        dissolved, and the root ended up as three disconnected components. _pick_incomplete_result_from_region()
        keeps only the one at the function address, so the other two were dropped from the output.

        The whole-binary CFG is required -- under a scoped CFG the region never reaches that state.
        """
        bin_path = os.path.join(test_location, "x86_64", "bbbq")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True, show_progressbar=False)
        proj.analyses.CompleteCallingConventions()
        proj.analyses.RustSymbolRecovery()
        proj.analyses.TypeDBLoader()

        incomplete = []

        class _Watch(logging.Handler):
            def emit(self, record):
                if "Structuring failed to complete" in record.getMessage():
                    incomplete.append(record)

        logger = logging.getLogger("angr.analyses.decompiler.structuring.recursive_structurer")
        watch = _Watch()
        logger.addHandler(watch)
        try:
            dec = proj.analyses.Decompiler(0x410920, cfg=cfg.model, flavor="rust", fail_fast=True)
        finally:
            logger.removeHandler(watch)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert not incomplete

        # the blocks that used to be dropped along with the discarded components
        structured = {b.addr for b in sequence_to_blocks(dec.seq_node)}
        for addr in (0x4115BA, 0x4115CC, 0x4115CF, 0x411435, 0x411458):
            assert addr in structured, f"{addr:#x} missing from the structured output"


if __name__ == "__main__":
    unittest.main()
