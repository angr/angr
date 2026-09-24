#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""Function graph storage: the transition graph lives in a Rust FunctionGraph and networkx views are materialized
on demand."""

from __future__ import annotations

import os
import pickle
import tempfile
import unittest

import networkx

import angr
from angr.angrdb import AngrDB
from angr.codenode import BlockNode, FuncNode, HookNode
from angr.knowledge_plugins.functions.transition_graph import TransitionGraph
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")
TRUE = os.path.join(bin_location, "tests", "x86_64", "true")


class TestFunctionRustGraph(unittest.TestCase):
    def test_materialized_views_and_node_identity(self):
        proj = angr.Project(FAUXWARE)
        func = proj.kb.functions.function(0x40071D, create=True)
        assert func is not None
        a = BlockNode(0x40071D, 4, bytestr=b"\x90" * 4)
        b = BlockNode(0x400721, 8)
        callee = FuncNode(0x400600)
        func.transit_to(a, b, ins_addr=0x40071F, stmt_idx=3)
        func.call_to(b, callee, None, ins_addr=0x400725, stmt_idx=-2)
        func.add_return_site(b)

        # the objects handed to the function stay the canonical objects
        assert func.get_node(0x40071D) is a
        assert func.startpoint is a
        assert func.ret_sites == [b]
        assert func.endpoints_with_type["return"] == {b}
        assert func.block_addrs_set == {0x40071D, 0x400721}
        assert list(func.block_addrs) == [0x40071D, 0x400721]
        assert func.get_block_size(0x400721) == 8
        assert 0x400721 in func and 0x400600 not in func
        assert func.size == 12
        assert func.has_return

        tg = func.transition_graph
        assert isinstance(tg, TransitionGraph)
        assert func.transition_graph is tg
        assert set(tg.nodes()) == {a, b, callee}
        assert tg[a][b] == {"type": "transition", "outside": False, "ins_addr": 0x40071F, "stmt_idx": 3}
        assert tg[b][callee] == {"type": "call", "ins_addr": 0x400725, "stmt_idx": -2}
        assert next(iter(tg.successors(a))) is b
        assert b.successors() == [callee]
        assert a.predecessors() == []
        assert set(func.graph.nodes()) == {a, b}
        assert func.graph is func.graph
        assert list(func.graph.edges()) == [(a, b)]
        assert [b.addr for b in func.blocks] == [0x40071D, 0x400721]
        assert func.code_nodes == {0x40071D: a, 0x400721: b}
        assert func.cyclomatic_complexity == 2 - 3 + 2

    def test_writes_keep_the_views_in_sync(self):
        proj = angr.Project(FAUXWARE)
        func = proj.kb.functions.function(0x40071D, create=True)
        assert func is not None
        a = BlockNode(0x40071D, 4)
        func.register_node(True, a)
        tg = func.transition_graph
        local = func.graph

        # Function API writes update the cached transition graph in place and invalidate the local view
        b = BlockNode(0x400721, 8)
        func.fakeret_to(a, b)
        assert func.transition_graph is tg
        assert tg[a][b] == {"type": "fake_return", "outside": False}
        assert func.graph is not local
        func.confirm_fakeret(a, b)
        assert tg[a][b]["confirmed"] is True
        assert 0x400721 in func.block_addrs_set
        func.remove_fakeret(a, b)
        assert not tg.has_edge(a, b)
        with self.assertRaises(networkx.NetworkXError):
            func.remove_fakeret(a, b)

        # the view is read-only; direct graph edits go through the Function API
        c = BlockNode(0x400729, 2)
        func._dirty = False
        with self.assertRaises(networkx.NetworkXError):
            tg.add_edge(a, c, type="transition", outside=False, ins_addr=0x40071F, stmt_idx=-2)
        assert not func.dirty and c not in tg
        func.add_graph_edge(a, c, type="transition", outside=False, ins_addr=0x40071F, stmt_idx=-2)
        assert func.dirty
        assert func._graph.number_of_edges() == 1
        cmsg = func.serialize_to_cmessage()
        loaded = angr.knowledge_plugins.Function.parse_from_cmessage(
            cmsg, function_manager=proj.kb.functions, project=proj
        )
        assert {(u.addr, v.addr, d["type"]) for u, v, d in loaded.transition_graph.edges(data=True)} == {
            (0x40071D, 0x400729, "transition")
        }
        with self.assertRaises(networkx.NetworkXError):
            tg.remove_node(c)
        func.remove_graph_node(c)
        assert func._graph.number_of_edges() == 0
        assert c not in func.transition_graph

    def test_copy_pickle_and_clear(self):
        proj = angr.Project(FAUXWARE)
        cfg = proj.analyses.CFGFast()
        main = cfg.kb.functions.function(name="main")
        assert main is not None
        sig = sorted((u.addr, v.addr, tuple(sorted(d.items()))) for u, v, d in main.transition_graph.edges(data=True))
        assert sig

        copied = main.copy()
        assert copied.transition_graph is not main.transition_graph
        assert (
            sorted((u.addr, v.addr, tuple(sorted(d.items()))) for u, v, d in copied.transition_graph.edges(data=True))
            == sig
        )
        assert copied.block_addrs_set == main.block_addrs_set
        assert copied.startpoint == main.startpoint

        unpickled = pickle.loads(pickle.dumps(main))
        assert (
            sorted(
                (u.addr, v.addr, tuple(sorted(d.items()))) for u, v, d in unpickled.transition_graph.edges(data=True)
            )
            == sig
        )
        assert unpickled.endpoints_with_type.keys() == main.endpoints_with_type.keys()
        assert unpickled.get_call_sites() == main.get_call_sites()

        main.clear_transition_graph()
        assert main.transition_graph.number_of_nodes() == 0
        assert main.startpoint is None
        assert not main.block_addrs_set

    def test_hook_nodes_survive_reload(self):
        proj = angr.Project(FAUXWARE)
        cfg = proj.analyses.CFGFast()
        plt_func = next(f for f in cfg.kb.functions.values() if f.is_plt)
        hook = next(n for n in plt_func.transition_graph.nodes() if isinstance(n, HookNode))
        cmsg = plt_func.serialize_to_cmessage()
        loaded = angr.knowledge_plugins.Function.parse_from_cmessage(
            cmsg, function_manager=proj.kb.functions, project=proj
        )
        reloaded_hook = next(n for n in loaded.transition_graph.nodes() if n.addr == hook.addr)
        assert isinstance(reloaded_hook, HookNode)
        assert reloaded_hook.sim_procedure is not None

    def test_angrdb_round_trip(self):
        proj = angr.Project(FAUXWARE)
        cfg = proj.analyses.CFGFast()
        before = {addr: _signature(f) for addr, f in cfg.kb.functions.items()}
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "fauxware.adb")
            AngrDB(proj).dump(path)
            proj2 = AngrDB().load(path)
        after = {addr: _signature(f) for addr, f in proj2.kb.functions.items()}
        assert before == after

    def test_cfg_with_spilling_matches_cfg_without(self):
        # a tiny cache limit forces almost every function through LMDB during recovery
        spilled = angr.Project(TRUE, cache_limits={"functions": 3})
        cfg_spilled = spilled.analyses.CFGFast()
        assert spilled.kb.functions.spilled_function_count > 0
        plain = angr.Project(TRUE, cache_limits={"functions": None})
        cfg_plain = plain.analyses.CFGFast()
        assert {n.addr for n in cfg_spilled.graph.nodes()} == {n.addr for n in cfg_plain.graph.nodes()}
        assert set(spilled.kb.functions) == set(plain.kb.functions)
        for addr in plain.kb.functions:
            assert _signature(spilled.kb.functions[addr]) == _signature(plain.kb.functions[addr]), hex(addr)


def _node(n):
    return (type(n).__name__, n.addr, n.size, bool(n.thumb))


def _signature(f):
    tg = f.transition_graph
    return (
        f.returning,
        None if f.startpoint is None else _node(f.startpoint),
        sorted(f.block_addrs_set),
        sorted(_node(n) for n in tg.nodes()),
        sorted((_node(u), _node(v), tuple(sorted(d.items()))) for u, v, d in tg.edges(data=True)),
        {k: sorted(_node(n) for n in v) for k, v in f.endpoints_with_type.items()},
        sorted(_node(n) for n in f.ret_sites),
        sorted(_node(n) for n in f.jumpout_sites),
        sorted(_node(n) for n in f.callout_sites),
        sorted((a, f.get_call_target(a), f.get_call_return(a)) for a in f.get_call_sites()),
    )


if __name__ == "__main__":
    unittest.main()
