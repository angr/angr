#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""The Rust-backed scan-time function store (RecoveryFunctions) and its RecoveryFunction views."""

from __future__ import annotations

import os
import unittest

import networkx

import angr
from angr.codenode import BlockNode, FuncNode, HookNode
from angr.knowledge_plugins.functions import FunctionManager
from angr.knowledge_plugins.functions.recovery import RecoveryFunction, RecoveryFunctionManager
from angr.rustylib.function_graph import NodeKind
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")

BLOCK = NodeKind.BLOCK


def _spec(addr, size, thumb=False):
    return (BLOCK, addr, size, thumb)


def _graph_state(func):
    """Everything the digest reads from a function graph, as hashable sets."""
    tg = func.transition_graph
    edges = {
        (type(s).__name__, s.addr, s.size, type(d).__name__, d.addr, d.size, tuple(sorted(data.items())))
        for s, d, data in tg.edges(data=True)
    }
    nodes = {(type(n).__name__, n.addr, n.size, n.thumb) for n in tg.nodes()}
    local = {(type(n).__name__, n.addr, n.size) for n in func.graph.nodes()}
    local_edges = {(s.addr, d.addr, tuple(sorted(data.items()))) for s, d, data in func.graph.edges(data=True)}
    return {
        "nodes": nodes,
        "edges": edges,
        "local": local,
        "local_edges": local_edges,
        "blocks": set(func.block_addrs_set),
        "startpoint": None if func.startpoint is None else func.startpoint.addr,
        "endpoints": {(n.addr, n.size) for n in func.endpoints},
        "ret": {n.addr for n in func.ret_sites},
        "jumpout": {n.addr for n in func.jumpout_sites},
        "retout": {n.addr for n in func.retout_sites},
        "call_sites": func.call_sites,
    }


def _drive(functions, fa, fb):
    """The same recovery sequence through either kind of FunctionManager."""
    a, b, c, d = 0x1000, 0x1010, 0x1020, 0x1030
    functions._add_node(fa, _spec(a, 16))
    functions._add_transition_to(fa, _spec(a, 16), _spec(b, 16), ins_addr=a + 12, stmt_idx=5)
    functions._add_call_to(fa, _spec(b, 16), fb, None, stmt_idx=-2, ins_addr=b + 11)
    functions._add_fakeret_to(fa, _spec(b, 16), _spec(c, 16), confirmed=None)
    functions._add_node(fb, _spec(fb, 8))
    functions._add_return_from(fb, _spec(fb, 8))
    functions._add_return_from_call(fa, fb, _spec(c, 16))
    functions._add_node(fa, _spec(c, 16))
    functions._add_outside_transition_to(fa, _spec(c, 16), _spec(d, 4), to_function_addr=d, ins_addr=c + 12, stmt_idx=3)
    functions._add_call_to(fa, _spec(d, 4), None, None)
    functions._add_fakeret_to(fa, _spec(d, 4), _spec(d + 4, 4), confirmed=True, to_outside=True, to_function_addr=d)
    functions._remove_fakeret(fa, _spec(d, 4), _spec(d + 4, 4))
    functions._add_return_from(fa, _spec(d + 4, 4))


class TestRecoveryFunctions(unittest.TestCase):
    def test_store_matches_codenode_api(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        fa, fb = 0x1000, 0x2000
        plain = FunctionManager(proj.kb)
        _drive(plain, fa, fb)
        rec = RecoveryFunctionManager(proj.kb)
        _drive(rec, fa, fb)

        for addr in (fa, fb):
            assert _graph_state(rec.get_by_addr(addr)) == _graph_state(plain.get_by_addr(addr))
            assert rec.get_by_addr(addr).returning == plain.get_by_addr(addr).returning
        assert set(rec.nonreturning_func_addrs()) == set(plain.nonreturning_func_addrs())
        assert set(rec.unknown_returning_func_addrs()) == set(plain.unknown_returning_func_addrs())
        assert sorted(rec) == sorted(plain)
        assert rec.get_func_block_count(fa) == plain.get_func_block_count(fa)
        assert sorted(rec.callgraph.edges(data=True), key=str) == sorted(plain.callgraph.edges(data=True), key=str)
        assert list(rec.callgraph.predecessors(fb)) == list(plain.callgraph.predecessors(fb))
        assert rec.ceiling_addr(fa + 1) == plain.ceiling_addr(fa + 1) == fb
        assert rec.floor_addr(fb - 1) == plain.floor_addr(fb - 1) == fa
        assert list(rec._function_map.irange(minimum=fa + 1, maximum=fb)) == [fb]

    def test_mirrors_update_incrementally(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        rec = RecoveryFunctionManager(proj.kb)
        fa, fb = 0x1000, 0x2000
        rec._add_node(fa, _spec(fa, 16))
        func = rec.get_by_addr(fa)
        assert isinstance(func, RecoveryFunction)
        # materialize the caches, then keep mutating through the store
        tg, lg, blocks = func.transition_graph, func.graph, func.block_addrs_set
        _drive(rec, fa, fb)
        assert func.transition_graph is tg
        assert func.block_addrs_set is blocks
        # like Function, the local view is rebuilt after a mutation
        assert func.graph is not lg

        plain = FunctionManager(proj.kb)
        plain._add_node(fa, _spec(fa, 16))
        pf = plain.get_by_addr(fa)
        _ = pf.transition_graph
        _drive(plain, fa, fb)
        assert _graph_state(func) == _graph_state(pf)
        assert [(s.addr, d.addr) for s, d in func.transition_graph.edges()] == [
            (s.addr, d.addr) for s, d in pf.transition_graph.edges()
        ]
        assert [n.addr for n in func.graph.nodes()] == [n.addr for n in pf.graph.nodes()]

    def test_local_view_reads_match_networkx(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        rec = RecoveryFunctionManager(proj.kb)
        fa, fb = 0x1000, 0x2000
        _drive(rec, fa, fb)
        rec._add_transition_to(fa, _spec(0x1020, 16), _spec(0x1000, 16))
        rec._add_transition_to(fa, _spec(0x1010, 16), _spec(0x1040, 16))
        rec._add_transition_to(fa, _spec(0x1000, 16), _spec(0x1040, 16))
        func = rec.get_by_addr(fa)
        g, tg = func.graph, func.transition_graph
        assert func.local_dfs_postorder(func.startpoint) == list(networkx.dfs_postorder_nodes(g, func.startpoint))
        for node in g:
            assert func.local_predecessors(node) == list(g.predecessors(node))
            assert func.local_out_edges(node) == [(d, dict(data)) for _, d, data in g.out_edges(node, data=True)]
            callees = [s for s in tg.successors(node) if isinstance(s, (FuncNode, HookNode))]
            assert func.first_callee_successor(node) == (callees[0] if callees else None)

    def test_flags_and_info_write_through(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        rec = RecoveryFunctionManager(proj.kb)
        func = rec.function(0x1000, create=True)
        assert func is not None
        assert func.returning is None and rec.is_func_returning_unknown(0x1000)
        func.returning = False
        assert rec.is_func_nonreturning(0x1000)
        func.info["gp"] = 0x1234
        func.info["is_alloca_probe"] = True
        assert (
            func.info.get("gp") == 0x1234
            and "gp" in func.info
            and dict(func.info)
            == {
                "gp": 0x1234,
                "is_alloca_probe": True,
            }
        )
        assert rec.store.info_int(0x1000, "gp") == 0x1234
        func.info = {"bp_as_gpr": True, "is_jmp_rax": True}
        assert rec.get_key_func_addrs("jmp_rax") == {0x1000}
        func.name = "foo"
        assert func.name == "foo" and func.previous_names == ["sub_1000"]
        assert rec.function(name="foo") is func
        assert rec.function(name="sub_1000", check_previous_names=True) is func
        func.is_plt = True
        assert func.is_plt and rec.get_by_addr(0x1000).is_plt
        del rec[0x1000]
        assert 0x1000 not in rec and 0x1000 not in rec.callgraph

    def test_python_mutators_on_views(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        rec = RecoveryFunctionManager(proj.kb)
        func = rec.function(0x1000, create=True)
        a = BlockNode(0x1000, 4)
        b = BlockNode(0x1004, 4)
        func.transit_to(a, b)
        func.call_to(b, FuncNode(0x2000), None)
        assert func.get_node(0x1000) is a
        assert rec.get_func_block_count(0x1000) == 2
        rec._add_transition_to(0x1000, _spec(0x1004, 4), _spec(0x1008, 4))
        assert set(func.block_addrs_set) == {0x1000, 0x1004, 0x1008}
        assert set(func.graph.successors(b)) == {func.get_node(0x1008)}

    def test_cfgfast_uses_and_drops_the_store(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        proj.kb.functions.function(0x40071D, name="pre_named", create=True)
        cfg = proj.analyses.CFGFast()
        assert cfg._recovery_functions
        assert type(proj.kb.functions) is FunctionManager
        assert proj.kb.functions[0x40071D].name == "pre_named"
        assert isinstance(proj.kb.functions.callgraph, networkx.MultiDiGraph)
        assert proj.kb.functions["pre_named"].returning


if __name__ == "__main__":
    unittest.main()
