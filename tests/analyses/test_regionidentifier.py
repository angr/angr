#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import networkx

import angr
from angr.ailment import Block
from angr.ailment.expression import Const, Register
from angr.ailment.statement import ConditionalJump, Jump, Return
from angr.analyses.decompiler.region_identifier import RegionIdentifier
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestRegionIdentifier(unittest.TestCase):
    def test_supergraph_merges_conditional_branch_after_call(self):
        for edge_type in ("fake_return", "transition"):
            with self.subTest(edge_type=edge_type):
                head = Block(0x400000, 5, statements=[])
                left = Block(0x40000F, 1, statements=[Return(0, [])])
                right = Block(0x400010, 1, statements=[Return(0, [])])
                branch = Block(
                    0x400005,
                    10,
                    statements=[
                        ConditionalJump(0, Register(1, 8, 1), Const(2, left.addr, 32), Const(3, right.addr, 32))
                    ],
                )
                graph = networkx.DiGraph()
                graph.add_edge(head, branch, type=edge_type)
                graph.add_edge(branch, left, type="transition")
                graph.add_edge(branch, right, type="transition")
                identifier = object.__new__(RegionIdentifier)
                identifier.entry_node_addr = (head.addr, None)
                identifier._make_supergraph(graph)  # pylint:disable=protected-access

                if edge_type == "fake_return":
                    assert len(graph) == 3
                    merged = next(node for node in graph if node.addr == head.addr)
                    assert merged.nodes == [head, branch]
                    assert set(graph.successors(merged)) == {left, right}
                else:
                    assert set(graph) == {head, branch, left, right}
                    assert graph.has_edge(head, branch)

    def test_supergraph_preserves_dispatch_address_after_call(self):
        for edge_type in ("fake_return", "transition"):
            for indirect in (False, True):
                with self.subTest(edge_type=edge_type, indirect=indirect):
                    head = Block(0x400000, 5, statements=[])
                    terminator = Jump(0, Register(1, 8, 32)) if indirect else Return(0, [])
                    dispatch = Block(0x400005, 10, statements=[terminator])
                    graph = networkx.DiGraph()
                    graph.add_edge(head, dispatch, type=edge_type)
                    identifier = object.__new__(RegionIdentifier)
                    identifier.entry_node_addr = (head.addr, None)
                    identifier._make_supergraph(graph)  # pylint:disable=protected-access

                    if indirect:
                        # Switch matching keys CFG jump-table metadata by the dispatch block's address.
                        assert set(graph) == {head, dispatch}
                        assert graph.has_edge(head, dispatch)
                    else:
                        assert len(graph) == 1
                        assert next(iter(graph)).addr == head.addr

    def test_smoketest(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False)
        cfg = p.analyses.CFG(normalize=True)

        main_func = cfg.kb.functions["main"]

        _ = p.analyses.RegionIdentifier(main_func)

    def test_make_supergraph_update_entrynode(self):
        proj = angr.Project(
            os.path.join(
                test_location, "i386", "windows", "a71a3c3b922705cb5e2d8aa9c74f5c73c47fb27f10b1327eb2bb054d99a14397"
            ),
            auto_load_libs=False,
        )
        cfg = proj.analyses.CFG(
            force_smart_scan=False,
            normalize=True,
            show_progressbar=True,
            regions=[(0x5E4746, 0x5E4910)],
            start_at_entry=False,
            function_starts=(0x5E47CA,),
        )

        the_func = cfg.kb.functions[0x5E47CA]

        # region identifier is invoked during decompilation of this function. shall not fail
        dec = proj.analyses.Decompiler(the_func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen.text


if __name__ == "__main__":
    unittest.main()
