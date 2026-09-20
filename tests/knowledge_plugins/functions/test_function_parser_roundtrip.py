#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""
Serialize/parse round trips of Function objects must be lossless: node kinds (HookNode/SyscallNode/FuncNode), Thumb
blocks, standalone fake-return edges, retout sites, and unset edge attributes (ins_addr/stmt_idx) all round trip.
These paths are what SpillingFunctionDict and angrdb use to store functions.
"""

from __future__ import annotations

import os
import unittest

import angr
from angr.codenode import BlockNode, FuncNode, HookNode
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.functions.function_parser import FunctionParser
from angr.protos import primitives_pb2
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
        {addr: a.get_block_size(addr) for addr in a.block_addrs_set},
        {addr: b.get_block_size(addr) for addr in b.block_addrs_set},
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

    def test_fake_return_only_edge(self):
        # a fall-through edge without a call edge from the same block (e.g. the call target was unresolvable)
        proj = self.proj
        fm = proj.kb.functions
        func = fm.function(addr=0x400664, create=True)
        src = proj.factory.snippet(0x400664)
        dst = proj.factory.snippet(0x40068E)
        fm._add_node(0x400664, src)
        fm._add_fakeret_to(0x400664, src, dst, confirmed=None)
        # an unconfirmed fake-return edge to a block that is not part of the function
        src2 = proj.factory.snippet(0x400699)
        ext = proj.factory.snippet(0x4006AF)
        fm._add_node(0x400664, src2)
        fm._add_fakeret_to(0x400664, src2, ext, confirmed=False)
        assert ext.addr not in func.block_addrs_set

        loaded = _roundtrip(func)
        _assert_graph_equal(self, func, loaded)
        self.assertEqual(loaded.transition_graph[src][dst], {"type": "fake_return", "outside": False})
        self.assertEqual(
            loaded.transition_graph[src2][ext], {"type": "fake_return", "outside": False, "confirmed": False}
        )
        self.assertNotIn(ext.addr, loaded.block_addrs_set)

    def test_local_hook_node_and_hooked_edge_targets(self):
        proj = self.proj
        fm = proj.kb.functions
        puts_addr = proj.loader.find_symbol("puts").rebased_addr
        assert proj.is_hooked(puts_addr)

        # the hooked function itself: a single local HookNode that is the start point and a return site
        hooked = fm.function(addr=puts_addr, create=True)
        hook_node = proj.factory.snippet(puts_addr)
        assert isinstance(hook_node, HookNode)
        fm._add_node(puts_addr, hook_node)
        fm._add_return_from(puts_addr, hook_node)

        loaded = _roundtrip(hooked)
        _assert_graph_equal(self, hooked, loaded)
        self.assertIsInstance(loaded.startpoint, HookNode)
        self.assertIs(loaded.startpoint.sim_procedure, proj.hooked_by(puts_addr))
        self.assertEqual([type(n) for n in loaded.ret_sites], [HookNode])

        # a caller: call and syscall edges target FuncNodes, a tail jump targets the HookNode
        caller = fm.function(addr=0x400664, create=True)
        src = proj.factory.snippet(0x400664)
        fm._add_call_to(0x400664, src, puts_addr, stmt_idx=-2, ins_addr=0x400689)
        src2 = proj.factory.snippet(0x400699)
        fm._add_call_to(0x400664, src2, puts_addr, syscall=True, stmt_idx=-2, ins_addr=0x4006AA)
        src3 = proj.factory.snippet(0x4006AF)
        fm._add_outside_transition_to(0x400664, src3, puts_addr, to_function_addr=puts_addr, ins_addr=0x4006C3)

        loaded = _roundtrip(caller)
        _assert_graph_equal(self, caller, loaded)
        kinds = {(src_.addr, data["type"]): type(dst_) for src_, dst_, data in loaded.transition_graph.edges(data=True)}
        self.assertIs(kinds[(0x400664, "call")], FuncNode)
        self.assertIs(kinds[(0x400699, "syscall")], FuncNode)
        self.assertIs(kinds[(0x4006AF, "transition")], HookNode)

    def test_thumb_blocks(self):
        proj = angr.Project(
            os.path.join(test_location, "armel", "fauxware"), auto_load_libs=False, cache_limits={"functions": None}
        )
        fm = proj.kb.functions
        func = fm.function(addr=0x8411, create=True)
        b0 = proj.factory.snippet(0x8411)
        b1 = proj.factory.snippet(0x8417)
        assert isinstance(b0, BlockNode) and b0.thumb and b1.thumb
        fm._add_node(0x8411, b0)
        fm._add_transition_to(0x8411, b0, b1, ins_addr=0x8415, stmt_idx=-2)
        fm._add_return_from(0x8411, b1)

        loaded = _roundtrip(func)
        _assert_graph_equal(self, func, loaded)
        self.assertTrue(all(n.thumb for n in loaded.transition_graph.nodes()))
        self.assertTrue(loaded.startpoint.thumb)
        self.assertEqual(loaded.get_node(0x8417).bytestr, b1.bytestr)

    def test_retout_site(self):
        proj = self.proj
        fm = proj.kb.functions
        func = fm.function(addr=0x400664, create=True)
        src = proj.factory.snippet(0x400664)
        ret = proj.factory.snippet(0x40068E)
        fm._add_call_to(0x400664, src, 0x400550, retn_node=ret, stmt_idx=-2, ins_addr=0x400689, return_to_outside=True)
        assert func.retout_sites == [src] and not func.has_return

        loaded = _roundtrip(func)
        _assert_graph_equal(self, func, loaded)
        self.assertEqual(loaded.retout_sites, [src])
        self.assertEqual(loaded.ret_sites, [])
        self.assertFalse(loaded.has_return)
        self.assertEqual(loaded.transition_graph[src][ret]["outside"], True)

        # a block that is both a return site and a retout site keeps both roles
        fm._add_return_from(0x400664, src)
        loaded = _roundtrip(func)
        _assert_graph_equal(self, func, loaded)
        self.assertTrue(loaded.has_return)
        self.assertEqual(loaded.retout_sites, [src])

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

    def test_legacy_message_without_node_kinds(self):
        # messages written before Block.kind/thumb existed still load: external functions are only listed by address
        proj = self.proj
        fm = proj.kb.functions
        puts_addr = proj.loader.find_symbol("puts").rebased_addr
        func = fm.function(addr=0x400664, create=True)
        src = proj.factory.snippet(0x400664)
        ret = proj.factory.snippet(0x40068E)
        fm._add_call_to(0x400664, src, 0x400550, retn_node=ret, stmt_idx=-2, ins_addr=0x400689)
        fm._add_fakeret_to(0x400664, src, ret, confirmed=True)
        fm._add_outside_transition_to(0x400664, ret, puts_addr, to_function_addr=puts_addr, ins_addr=0x400690)
        fm._add_return_from(0x400664, ret)

        cmsg = FunctionParser.serialize(func, legacy_layout=True)
        assert not cmsg.graph_blob
        legacy_external = [b for b in cmsg.external_blocks if b.kind == primitives_pb2.CodeNodeKind.BLOCK_NODE]
        del cmsg.external_blocks[:]
        cmsg.external_blocks.extend(legacy_external)
        for block in list(cmsg.blocks) + list(cmsg.external_blocks):
            block.ClearField("kind")
            block.ClearField("thumb")
        assert cmsg.external_functions

        loaded = Function.parse_from_cmessage(cmsg, function_manager=fm, project=proj)
        _assert_graph_equal(self, func, loaded)

    def test_per_edge_layout_round_trips(self):
        # the per-block/per-edge layout (written by angr before graph_blob existed) stays lossless
        proj = self.proj
        fm = proj.kb.functions
        puts_addr = proj.loader.find_symbol("puts").rebased_addr
        func = fm.function(addr=0x400664, create=True)
        src = proj.factory.snippet(0x400664)
        ret = proj.factory.snippet(0x40068E)
        fm._add_call_to(0x400664, src, 0x400550, retn_node=ret, stmt_idx=-2, ins_addr=0x400689)
        fm._add_fakeret_to(0x400664, src, ret, confirmed=True)
        fm._add_outside_transition_to(0x400664, ret, puts_addr, to_function_addr=puts_addr, ins_addr=0x400690)
        fm._add_return_from(0x400664, ret)
        src2 = proj.factory.snippet(0x400699)
        ext = proj.factory.snippet(0x4006AF)
        fm._add_node(0x400664, src2)
        fm._add_fakeret_to(0x400664, src2, ext, confirmed=False)
        fm._add_call_to(0x400664, src2, 0x400550, retn_node=src, stmt_idx=-2, ins_addr=0x4006AA, return_to_outside=True)

        cmsg = FunctionParser.serialize(func, legacy_layout=True)
        assert not cmsg.graph_blob and cmsg.blocks and cmsg.graph.edges
        loaded = Function.parse_from_cmessage(cmsg, function_manager=fm, project=proj)
        _assert_graph_equal(self, func, loaded)
        meta = Function.parse_from_cmessage(cmsg, function_manager=fm, project=proj, meta_only=True)
        self.assertEqual(meta.block_addrs_set, func.block_addrs_set)
        self.assertEqual(set(meta.retout_sites), set(func.retout_sites))
        self.assertEqual(set(meta.ret_sites), set(func.ret_sites))


if __name__ == "__main__":
    unittest.main()
