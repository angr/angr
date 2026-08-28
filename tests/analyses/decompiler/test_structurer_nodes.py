#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr import ailment
from angr.analyses.decompiler.structurer_nodes import CodeNode, LoopNode, SequenceNode


class TestStructurerNodeAddresses(unittest.TestCase):
    def test_codenode_addr_is_fixed_at_construction(self):
        node = CodeNode(ailment.Block(0x400000, 0), None)
        assert node.addr == 0x400000

        # replacing the inner node must not move the CodeNode
        node.node = SequenceNode(0x400100, nodes=[])
        assert node.addr == 0x400000

    def test_codenode_addr_is_none_without_an_inner_addr(self):
        assert CodeNode(None, None).addr is None

    def test_codenode_copy_preserves_addr(self):
        node = CodeNode(ailment.Block(0x400000, 0, idx=3), None)
        assert (node.addr, node.idx) == (0x400000, 3)
        assert (node.copy().addr, node.copy().idx) == (0x400000, 3)

    def test_loopnode_addr_is_fixed_at_construction(self):
        loop = LoopNode("while", None, SequenceNode(0x400000, nodes=[]))
        assert loop.addr == 0x400000
        assert loop.continue_addr == 0x400000

        loop.sequence_node = SequenceNode(0x400100, nodes=[])
        assert loop.addr == 0x400000

    def test_loopnode_explicit_addrs_win_and_survive_copy(self):
        loop = LoopNode("while", None, SequenceNode(0x400100, nodes=[]), addr=0x400000, continue_addr=0x400080)
        assert (loop.addr, loop.continue_addr) == (0x400000, 0x400080)
        copied = loop.copy()
        assert (copied.addr, copied.continue_addr) == (0x400000, 0x400080)


if __name__ == "__main__":
    unittest.main()
