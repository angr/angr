#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""
Serialize/parse round trips of Function objects must be lossless: unset edge attributes (ins_addr/stmt_idx) round trip.
These paths are what SpillingFunctionDict and angrdb use to store functions.
"""

from __future__ import annotations

import os
import unittest

import angr
from angr.codenode import FuncNode
from angr.knowledge_plugins.functions.function import Function
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _node_key(node):
    return (type(node).__name__, node.addr, node.size, node.thumb)


def _edges(func) -> set[tuple]:
    return {
        (_node_key(src), _node_key(dst), tuple(sorted(data.items())))
        for src, dst, data in func.transition_graph.edges(data=True)
    }


def _roundtrip(func: Function) -> Function:
    fm = func._function_manager
    assert fm is not None
    cmsg = func.serialize_to_cmessage()
    parsed = angr.knowledge_plugins.Function._get_cmsg()
    parsed.ParseFromString(cmsg.SerializeToString())
    return Function.parse_from_cmessage(parsed, function_manager=fm, project=func.project)


def _assert_graph_equal(tc: unittest.TestCase, a: Function, b: Function):
    tc.assertEqual(set(a.transition_graph.nodes()), set(b.transition_graph.nodes()))
    tc.assertEqual(
        {_node_key(n) for n in a.transition_graph.nodes()}, {_node_key(n) for n in b.transition_graph.nodes()}
    )
    tc.assertEqual(_edges(a), _edges(b))
    tc.assertEqual(a.block_addrs_set, b.block_addrs_set)
    tc.assertEqual(
        {addr: a._block_sizes[addr] for addr in a.block_addrs_set},
        {addr: b._block_sizes[addr] for addr in b.block_addrs_set},
    )
    tc.assertEqual(
        {k: set(v) for k, v in a.endpoints_with_type.items()}, {k: set(v) for k, v in b.endpoints_with_type.items()}
    )
    tc.assertEqual(set(a.ret_sites), set(b.ret_sites))
    tc.assertEqual(set(a.retout_sites), set(b.retout_sites))
    tc.assertEqual(set(a.jumpout_sites), set(b.jumpout_sites))
    tc.assertEqual(set(a.callout_sites), set(b.callout_sites))
    tc.assertEqual(a.has_return, b.has_return)
    tc.assertEqual(_node_key(a.startpoint), _node_key(b.startpoint))
    tc.assertEqual(a._call_sites, b._call_sites)


class TestFunctionParserRoundtrip(unittest.TestCase):
    def setUp(self):
        # each test builds its own functions
        self.proj = angr.Project(
            os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False, cache_limits={"functions": None}
        )

    def test_none_and_zero_ins_addr_stmt_idx(self):
        proj = self.proj
        fm = proj.kb.functions
        func = fm.function(addr=0x400664, create=True)
        b0 = proj.factory.snippet(0x400664)
        b1 = proj.factory.snippet(0x40068E)
        b2 = proj.factory.snippet(0x400699)
        fm._add_transition_to(0x400664, b0, b1)  # ins_addr=None, stmt_idx=None
        fm._add_transition_to(0x400664, b1, b2, ins_addr=0, stmt_idx=0)
        fm._add_call_to(0x400664, b2, 0x400550)  # stmt_idx=None, ins_addr=None on a call edge

        loaded = _roundtrip(func)
        _assert_graph_equal(self, func, loaded)
        self.assertEqual(
            loaded.transition_graph[b0][b1],
            {"type": "transition", "outside": False, "ins_addr": None, "stmt_idx": None},
        )
        self.assertEqual(
            loaded.transition_graph[b1][b2], {"type": "transition", "outside": False, "ins_addr": 0, "stmt_idx": 0}
        )
        self.assertEqual(
            loaded.transition_graph[b2][FuncNode(0x400550)], {"type": "call", "ins_addr": None, "stmt_idx": None}
        )


if __name__ == "__main__":
    unittest.main()
