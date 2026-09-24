#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""
CodeNode.successors()/predecessors() are answered by the owning Function's graph store, without a networkx graph.
"""

from __future__ import annotations

import gc
import os
import pickle
import unittest

import networkx

import angr
from angr.codenode import BlockNode, FuncNode, HookNode, SyscallNode
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


class TestCodeNodeOwner(unittest.TestCase):
    def test_neighbors_come_from_the_store(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        func = proj.kb.functions.function(0x40071D, create=True)
        assert func is not None
        a = BlockNode(0x40071D, 4)
        b = BlockNode(0x400721, 8)
        puts = proj.loader.find_symbol("puts").rebased_addr
        hook = HookNode(puts, 0, proj.hooked_by(puts))
        callee = FuncNode(0x400664)
        func.transit_to(a, b, ins_addr=0x40071F, stmt_idx=-2)
        func.call_to(b, callee, None, stmt_idx=-2, ins_addr=0x400725)
        func.transit_to(b, hook, outside=True, ins_addr=0x400725, stmt_idx=-2)
        assert func._transition_graph is None

        assert a.owner is func and b.owner is func and hook.owner is func and callee.owner is func
        assert a.successors() == [b] and a.predecessors() == []
        assert b.predecessors() == [a] and set(b.successors()) == {callee, hook}
        assert callee.successors() == [] and callee.predecessors() == [b]
        assert hook.predecessors() == [b]
        assert func._transition_graph is None  # no networkx view was materialized

        # an equal but distinct node object registered later also knows its owner
        a2 = BlockNode(0x40071D, 4)
        assert a2.owner is None
        with self.assertRaises(ValueError):
            a2.successors()
        assert func._register_node(True, a2) is a
        assert a2.owner is func and a2.successors() == [b]

        # a node that is not in the graph
        with self.assertRaises(networkx.NetworkXError):
            func._successors_of(BlockNode(0x500000, 1))

        # the view, once materialized, agrees
        assert set(func.transition_graph.successors(b)) == set(b.successors())

    def test_syscall_and_reloaded_nodes(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        for func in cfg.kb.functions.values():
            for node in func.transition_graph.nodes():
                assert node.owner is func
                assert set(node.successors()) == set(func.transition_graph.successors(node))
                assert set(node.predecessors()) == set(func.transition_graph.predecessors(node))
        main = cfg.kb.functions["main"]
        loaded = angr.knowledge_plugins.Function.parse(
            main.serialize(), function_manager=cfg.kb.functions, project=proj
        )
        assert loaded._transition_graph is None
        start = loaded.startpoint
        assert start.owner is loaded
        assert {n.addr for n in start.successors()} == {n.addr for n in main.startpoint.successors()}
        assert loaded._transition_graph is None
        assert any(isinstance(n, SyscallNode | HookNode) for f in cfg.kb.functions.values() for n in f.transition_graph)

    def test_owner_is_weak_and_not_pickled(self):
        proj = angr.Project(FAUXWARE, auto_load_libs=False)
        func = proj.kb.functions.function(0x40071D, create=True)
        assert func is not None
        a = BlockNode(0x40071D, 4)
        b = BlockNode(0x400721, 8)
        func.transit_to(a, b)
        unpickled = pickle.loads(pickle.dumps(a))
        assert unpickled == a and unpickled.owner is None
        with self.assertRaises(ValueError):
            unpickled.successors()
        assert hash(unpickled) == hash(a)
        del proj.kb.functions[0x40071D]
        del func
        gc.collect()
        assert a.owner is None
        with self.assertRaises(ValueError):
            a.successors()


if __name__ == "__main__":
    unittest.main()
