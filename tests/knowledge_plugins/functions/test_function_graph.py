#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

import os
import pickle
import unittest
from unittest import mock

import networkx

import angr
from angr.codenode import BlockNode, FuncNode, HookNode
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.functions.function_manager import FunctionManager
from angr.knowledge_plugins.functions.transition_graph import TransitionGraph
from angr.rustylib.function_graph import EdgeKind, FunctionGraph, SiteKind
from tests.common import bin_location

from .test_function_graph_serialization import function_digest

test_location = os.path.join(bin_location, "tests")


class TestFunctionGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)

    def _new_function(self, addr=0x500000):
        return Function(
            self.proj.kb.functions,
            addr,
            name=f"f_{addr:x}",
            syscall=False,
            is_simprocedure=False,
            is_plt=False,
            returning=True,
        )

    def test_build_read_and_materialize(self):
        func = self._new_function()
        b0 = BlockNode(0x500000, 8, bytestr=b"\x90" * 8)
        b1 = BlockNode(0x500008, 4, bytestr=b"\x90" * 4)
        b2 = BlockNode(0x50000C, 2, bytestr=b"\x90\xc3")
        callee = FuncNode(0x400664)

        func.transit_to(b0, b1, ins_addr=0x500006, stmt_idx=3)
        func.call_to(b1, callee, b2, stmt_idx=-2, ins_addr=0x500008)
        func.add_return_site(b2)

        # nothing is materialized yet; the store is the source of truth
        g = func._graph
        assert isinstance(g, FunctionGraph)
        assert func._transition_graph is None
        assert g.number_of_nodes() == 4 and g.number_of_edges() == 3 and g.local_count() == 3
        assert func.block_addrs_set == {0x500000, 0x500008, 0x50000C}
        assert func.startpoint is b0
        assert func.get_node(0x500008) is b1
        assert func.ret_sites == [b2]
        assert {n.addr for n in func.endpoints} == {0x50000C}
        assert 0x500008 in func and 0x400664 not in func  # only registered nodes count, not callees
        assert func.get_block_size(0x500000) == 8

        assert b0.successors() == [b1]
        assert b2.predecessors() == [b1]

        view = func.transition_graph
        assert isinstance(view, TransitionGraph)
        assert func.transition_graph is view
        assert set(view.nodes()) == {b0, b1, b2, callee}
        assert view[b0][b1] == {"type": "transition", "outside": False, "ins_addr": 0x500006, "stmt_idx": 3}
        assert view[b1][callee] == {"type": "call", "ins_addr": 0x500008, "stmt_idx": -2}
        assert view[b1][b2] == {"type": "fake_return", "outside": False}
        assert func.cyclomatic_complexity == 3 - 4 + 2

        # local graph excludes the callee and the call edge
        assert set(func.graph.nodes()) == {b0, b1, b2}
        assert func.graph.number_of_edges() == 2

    def test_view_stays_in_sync_with_function_writes(self):
        func = self._new_function()
        b0 = BlockNode(0x500000, 8, bytestr=b"\x90" * 8)
        b1 = BlockNode(0x500008, 4, bytestr=b"\x90" * 4)
        func.transit_to(b0, b1)
        view = func.transition_graph
        local = func.graph

        b2 = BlockNode(0x50000C, 2, bytestr=b"\x90\xc3")
        func.fakeret_to(b1, b2, confirmed=None)
        assert view.has_edge(b1, b2)
        assert "confirmed" not in view[b1][b2]
        assert func.graph is not local  # the local graph cache is invalidated

        func.confirm_fakeret(b1, b2)
        assert view[b1][b2]["confirmed"] is True
        assert 0x50000C in func.block_addrs_set

        func.remove_fakeret(b1, b2)
        assert not view.has_edge(b1, b2)
        with self.assertRaises(networkx.NetworkXError):
            func.remove_fakeret(b1, b2)

    def test_networkx_writes_are_rejected_and_the_function_api_edits_the_store(self):
        func = self._new_function()
        b0 = BlockNode(0x500000, 8, bytestr=b"\x90" * 8)
        func.register_node(True, b0)
        view = func.transition_graph
        func._dirty = False

        ext = BlockNode(0x600000, 4, bytestr=b"\x00" * 4)
        with self.assertRaises(networkx.NetworkXError):
            view.add_node(ext)
        with self.assertRaises(networkx.NetworkXError):
            view.add_edge(b0, ext, type="transition")
        assert not func.dirty and ext not in view and func._graph.number_of_edges() == 0

        func.add_graph_node(ext)
        func.add_graph_edge(b0, ext, type="transition", outside=True, ins_addr=0x500006, stmt_idx=-2)
        assert func.dirty
        assert func._graph.number_of_edges() == 1
        assert view[b0][ext] == {"type": "transition", "outside": True, "ins_addr": 0x500006, "stmt_idx": -2}
        assert ext.successors() == [] and ext.predecessors() == [b0]

        func.remove_edge(b0, ext)
        assert func._graph.number_of_edges() == 0 and not view.has_edge(b0, ext)
        func.remove_graph_node(ext)
        assert not func.has_node(ext)
        assert set(view.nodes()) == {b0}

        # copies are detached plain graphs
        copy = networkx.DiGraph(view)
        copy.add_node(ext)
        assert not func.has_node(ext)
        assert not isinstance(copy, TransitionGraph)
        assert type(view.copy()) is networkx.DiGraph

    def test_same_address_different_size_nodes(self):
        # networkx keys nodes by (type, addr, size, thumb); a second, smaller node at a known address only becomes a
        # vertex once an edge references it
        func = self._new_function()
        big = BlockNode(0x500000, 8, bytestr=b"\x90" * 8)
        small = BlockNode(0x500000, 4, bytestr=b"\x90" * 4)
        func.register_node(True, big)
        func.register_node(True, small)
        assert func._graph.number_of_nodes() == 1
        assert set(func.transition_graph.nodes()) == {big}
        assert func.code_nodes[0x500000] is big
        assert func.get_block_size(0x500000) == 8
        nxt = BlockNode(0x500004, 4, bytestr=b"\x90" * 4)
        func.transit_to(small, nxt)
        assert set(func.transition_graph.nodes()) == {big, small, nxt}
        assert func.get_node(0x500000) is big

    def test_hook_nodes_survive_round_trip(self):
        func = self._new_function()
        b0 = BlockNode(0x500000, 8, bytestr=b"\x90" * 8)
        hook = HookNode(0x700000, 0, self.proj.hooked_by(0x700000))
        func.call_to(b0, hook, None, stmt_idx=-2, ins_addr=0x500003)
        loaded = Function.parse(func.serialize(), function_manager=self.proj.kb.functions, project=self.proj)
        assert function_digest(loaded) == function_digest(func)
        (hook_loaded,) = (n for n in loaded.transition_graph if isinstance(n, HookNode))
        assert hook_loaded == hook and hook_loaded.sim_procedure is not None

    def test_copy_is_independent(self):
        func = self._new_function()
        b0 = BlockNode(0x500000, 8, bytestr=b"\x90" * 8)
        b1 = BlockNode(0x500008, 4, bytestr=b"\x90" * 4)
        func.transit_to(b0, b1)
        func.add_return_site(b1)
        clone = func.copy()
        assert function_digest(clone) == function_digest(func)
        clone.transit_to(b1, BlockNode(0x50000C, 2, bytestr=b"\x90\xc3"))
        assert clone._graph.number_of_edges() == 2 and func._graph.number_of_edges() == 1
        assert clone.block_addrs_set != func.block_addrs_set

    def test_pickle_round_trip_without_objects(self):
        func = self._new_function()
        b0 = BlockNode(0x500000, 8, bytestr=b"\x90" * 8)
        b1 = BlockNode(0x500008, 4, bytestr=b"\x90" * 4)
        func.transit_to(b0, b1, ins_addr=0x500006, stmt_idx=-2)
        func.add_return_site(b1)
        g = pickle.loads(pickle.dumps(func._graph))
        assert g.number_of_nodes() == 2 and g.number_of_edges() == 1
        assert g.edge_kind(0, 1) == EdgeKind.TRANSITION
        assert g.has_site(1, SiteKind.RET)
        assert g.to_bytes() == func._graph.to_bytes()
        # a Function unpickles without node objects and recreates them on demand
        f2 = pickle.loads(pickle.dumps(func))
        assert not f2._node_objs
        assert f2.startpoint == b0 and f2.ret_sites == [b1]

    def test_normalize_with_the_live_store(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        for func in proj.kb.functions.values():
            if func.startpoint is None or func.is_simprocedure:
                continue
            assert func.normalized
            # no two local blocks overlap after normalization
            blocks = sorted((n.addr, n.size) for n in func.code_nodes.values() if isinstance(n, BlockNode))
            for (a0, s0), (a1, _) in zip(blocks, blocks[1:]):
                assert a0 + s0 <= a1
            # a reloaded normalized function is identical to the live one
            loaded = Function.parse(func.serialize(), function_manager=proj.kb.functions, project=proj)
            assert function_digest(loaded) == function_digest(func)

    def test_normalize_splits_the_start_node(self):
        # the start block overlaps a smaller block that ends at the same address: normalize() shrinks the start block
        func = self._new_function(0x400664)  # fauxware: authenticate
        big = BlockNode(0x400664, 42, bytestr=None)
        small = BlockNode(0x400680, 14, bytestr=None)
        nxt = BlockNode(0x40068E, 4, bytestr=None)
        func.transit_to(big, nxt, ins_addr=0x400689, stmt_idx=-2)
        func.transit_to(small, nxt, ins_addr=0x400689, stmt_idx=-2)
        func.normalize()
        assert func.normalized
        assert func.startpoint is not None and func.startpoint.addr == 0x400664 and func.startpoint.size == 28
        assert func.code_nodes[0x400664].size == 28
        assert func.get_node(0x400664) is func.startpoint
        assert set(func.transition_graph.successors(func.startpoint)) == {small}
        assert set(func.graph.nodes()) == {func.startpoint, small, nxt}


class TestCFGEquivalenceWithSpilling(unittest.TestCase):
    def test_cfg_is_identical_with_a_tiny_function_cache(self):
        """
        Recover the CFG with functions constantly spilled to LMDB and reloaded, and compare it with a recovery that
        keeps everything in memory.
        """
        bin_path = os.path.join(test_location, "x86_64", "fauxware")

        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        assert not hasattr(proj.kb.functions._function_map, "spilled_count")
        reference = {addr: function_digest(f) for addr, f in proj.kb.functions.items()}

        # keep 20 functions in memory and evict one at a time; CFG recovery holds evicted Function objects with a
        # smaller cache and its own writes go stale (a documented SpillingFunctionDict limitation)
        with mock.patch.object(FunctionManager, "get_default_cache_limit", return_value=20):
            proj2 = angr.Project(bin_path, auto_load_libs=False)
            proj2.kb.functions._function_map._db_batch_size = 1
            cfg2 = proj2.analyses.CFGFast()
        fm = proj2.kb.functions._function_map
        assert fm.spilled_count > 0
        assert cfg2.graph.number_of_nodes() == cfg.graph.number_of_nodes()
        assert cfg2.graph.number_of_edges() == cfg.graph.number_of_edges()
        assert {addr: function_digest(f) for addr, f in proj2.kb.functions.items()} == reference


if __name__ == "__main__":
    unittest.main()
