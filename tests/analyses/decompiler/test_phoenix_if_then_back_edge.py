#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

import unittest
from unittest.mock import patch

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import Const, Register
from angr.ailment.statement import ConditionalJump, Jump, Return
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.structurer_nodes import ConditionNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer
from angr.analyses.decompiler.utils import sequence_to_blocks


class TestPhoenixIfThenBackEdge(unittest.TestCase):
    def test_return_guard_preserves_transfer_to_region_head(self):
        # An acyclic region inside a loop can end in `if (done) return; goto head;`.
        # If it dissolves, the transfer to head may become an enclosing loop's exit.
        # A graph edge alone is insufficient: cyclic refinement searches for a jump.
        for back_edge in (False, True):
            for reverse in (False, True):
                with self.subTest(back_edge=back_edge, reverse=reverse):
                    self._check_return_guard(back_edge, reverse)

    def _check_return_guard(self, back_edge, reverse):
        project = angr.load_shellcode(b"\xc3", arch="AMD64")
        manager = Manager()

        head = Block(0x400000, 4, statements=[], idx=3)
        ret = Block(0x400020, 4, statements=[Return(manager.next_atom(), [], ins_addr=0x400020)])
        targets = [head.addr, ret.addr] if reverse else [ret.addr, head.addr]
        indices = [head.idx, ret.idx] if reverse else [ret.idx, head.idx]
        guard = Block(
            0x400010,
            4,
            statements=[
                ConditionalJump(
                    manager.next_atom(),
                    Register(manager.next_atom(), 16, 1),
                    Const(manager.next_atom(), targets[0], 64),
                    Const(manager.next_atom(), targets[1], 64),
                    true_target_idx=indices[0],
                    false_target_idx=indices[1],
                    ins_addr=0x400010,
                )
            ],
        )
        graph = networkx.DiGraph([(head, guard), (guard, head), (guard, ret)])
        overlay = OverlayManager(graph)
        overlay.root.head = head if back_edge else guard
        with patch.object(PhoenixStructurer, "_analyze"):
            structurer = project.analyses[PhoenixStructurer].prep(fail_fast=True)(overlay.root, ail_manager=manager)
        assert structurer._match_acyclic_ite(
            overlay.root.graph, overlay.root.graph_with_successors, guard, overlay.root.head
        )
        result = next(node for node in overlay.root.graph if node is not head)
        assert isinstance(result.nodes[1], ConditionNode)
        blocks = sequence_to_blocks(result)
        assert ret in blocks
        jumps = [stmt for block in blocks for stmt in block.statements if isinstance(stmt, Jump)]
        assert len(jumps) == int(back_edge)
        if back_edge:
            assert jumps[0].target.value == head.addr
            assert jumps[0].target_idx == head.idx
            assert structurer._find_node_going_to_dst(result, head, enter_loops=False)[2] is not None


if __name__ == "__main__":
    unittest.main()
