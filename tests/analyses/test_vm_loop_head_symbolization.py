#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import inspect
import unittest

import networkx

from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation
from angr.knowledge_plugins.cfg.block_id import BlockID

RSI, RAX, RCX = (64, 8), (16, 8), (24, 8)


class _Node:
    def __init__(self, addr, vpc):
        self.block_id = BlockID.new(addr, (), "normal", vpc)

    def __repr__(self):
        return f"<{self.block_id.addr:#x} {self.block_id.vm_vpc}>"


def _graph(edges, native=()):
    """Nodes by name; those in `native` have no VPC."""
    nodes = {}
    graph = networkx.DiGraph()
    for src, dst in edges:
        for name in (src, dst):
            if name not in nodes:
                i = len(nodes)
                nodes[name] = _Node(0x1000 + i, None if name in native else 0x5000 + i)
        graph.add_edge(nodes[src], nodes[dst])
    return graph, {k: v.block_id for k, v in nodes.items()}


class TestLoopHeadTargets(unittest.TestCase):
    """Which block ids a symbolize_loop_heads pass symbolizes at."""

    def test_head_of_a_loop_with_a_data_exit(self):
        # for (i = 0; i < 20; i++) { if (fail) return; } -- the return is an exit edge, the i == 20 one is missing
        graph, b = _graph([("s", "h"), ("h", "x"), ("x", "h"), ("x", "r")])
        loops, targets, _ = VMDeobfuscation._loop_head_targets(graph, set(), set())
        assert len(loops) == 1
        assert targets == {b["h"]}

    def test_native_loop_is_not_a_vm_loop(self):
        graph, _ = _graph([("s", "h"), ("h", "x"), ("x", "h")], native={"s", "h", "x"})
        loops, targets, _ = VMDeobfuscation._loop_head_targets(graph, set(), set())
        assert not loops and not targets

    def test_tried_head_is_not_a_target_again(self):
        graph, b = _graph([("s", "h"), ("h", "x"), ("x", "h")])
        tried = {b["h"]}
        _, targets, _ = VMDeobfuscation._loop_head_targets(graph, tried, {b["h"]})
        assert not targets

    def test_moved_head_marks_the_loop_it_reaches_tried(self):
        # the old head h now runs once before the loop, which is entered at l1 and has its exit
        graph, b = _graph([("s", "h"), ("h", "e"), ("e", "l1"), ("l1", "l2"), ("l2", "l1"), ("l2", "m"), ("s", "m")])
        tried = {b["h"]}
        _, targets, no_longer = VMDeobfuscation._loop_head_targets(graph, tried, {b["h"]})
        assert no_longer == {b["h"]}
        assert not targets
        assert b["l1"] in tried

    def test_moved_head_into_an_exitless_loop_still_targets_it(self):
        graph, b = _graph([("s", "h"), ("h", "l1"), ("l1", "l2"), ("l2", "l1")])
        _, targets, _ = VMDeobfuscation._loop_head_targets(graph, {b["h"]}, {b["h"]})
        assert targets == {b["l1"]}

    def test_vanished_loop_targets_downstream_merge_points_once(self):
        # no loop is left after h: the back edge now joins at m
        graph, b = _graph([("s", "h"), ("h", "x"), ("x", "m"), ("s", "m"), ("m", "z")])
        tried, as_head = {b["h"]}, {b["h"]}
        _, targets, no_longer = VMDeobfuscation._loop_head_targets(graph, tried, as_head)
        assert targets == {b["m"]}
        as_head -= no_longer
        tried |= targets
        _, targets, _ = VMDeobfuscation._loop_head_targets(graph, tried, as_head)
        assert not targets


class TestHeadSymbolizations(unittest.TestCase):
    """The symbolizer's merge-point findings, restricted to loop heads."""

    def setUp(self):
        _, self.b = _graph([("h", "x"), ("g", "y"), ("m", "z"), ("t", "u")])

    def test_only_heads_kept_and_deduplicated(self):
        b = self.b
        to_symbolize = {
            b["h"]: {"reg": [(0, 32, 8), (0, 32, 8)], "mem": [(0x7FFF0000, 0x40, 8)]},
            b["m"]: {"reg": [(0, 24, 8)]},  # an ordinary merge point
            b["t"]: {"mem": [(0x7FFF0000, 0x48, 8)]},  # a head tried in an earlier pass
        }
        kept = VMDeobfuscation._head_symbolizations(to_symbolize, {b["t"]}, {b["h"]}, {b["h"]: RSI})
        assert set(kept) == {b["h"], b["t"]}
        assert kept[b["h"]]["reg"] == [(0, 32, 8)]

    def test_head_where_the_vip_differs_is_dropped(self):
        b = self.b
        to_symbolize = {b["h"]: {"reg": [(0, 64, 8), (0, 24, 8)]}, b["g"]: {"reg": [(0, 24, 8)]}}
        kept = VMDeobfuscation._head_symbolizations(to_symbolize, set(), {b["h"], b["g"]}, {b["h"]: RSI})
        assert set(kept) == {b["g"]}

    def test_vip_register_most_merge_points_record(self):
        # the head's own record names the handler's decoding register; the VM's VIP register (rsi) differs there
        b = self.b
        to_symbolize = {b["h"]: {"reg": [(0, 64, 8)]}}
        vpc_regs = {b["h"]: RAX, b["g"]: RSI, b["m"]: RSI, b["t"]: RSI}
        kept = VMDeobfuscation._head_symbolizations(to_symbolize, set(), {b["h"]}, vpc_regs)
        assert not kept

    def test_option(self):
        param = inspect.signature(VMDeobfuscation.__init__).parameters["symbolize_loop_heads"]
        assert param.default is False


if __name__ == "__main__":
    unittest.main()
