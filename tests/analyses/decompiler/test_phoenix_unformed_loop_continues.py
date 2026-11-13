#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest
from unittest import mock

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import BinaryOp, Const, Register
from angr.ailment.statement import ConditionalJump, Jump, Return
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structurer_nodes import ContinueNode, LoopNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer


class TestPhoenixUnformedLoopContinues(unittest.TestCase):
    def test_continues_become_gotos_when_the_loop_is_not_formed(self):
        # the loop of libc 0x529180 (a binary search): H -> B, D; B -> C, X; C -> H, E; D -> H, E; E, X -> S.
        # cyclic refinement turns C -> H into a continue. when no loop is formed afterwards (the last-resort
        # refinement virtualizes D -> H), that continue is outside any loop and must be a goto to H again.
        project = angr.load_shellcode(b"\xc3", arch="x86", load_address=0x400000)
        manager = Manager()

        def const(value):
            return Const(manager.next_atom(), value, 32)

        def cond_block(addr, reg, true_addr, false_addr):
            cond = BinaryOp(
                manager.next_atom(), "CmpEQ", [Register(manager.next_atom(), reg, 32), const(0)], False, bits=1
            )
            return Block(
                addr,
                4,
                statements=[
                    ConditionalJump(manager.next_atom(), cond, const(true_addr), const(false_addr), ins_addr=addr)
                ],
            )

        def goto_block(addr, target):
            return Block(addr, 4, statements=[Jump(manager.next_atom(), const(target), ins_addr=addr)])

        h_addr, b_addr, c_addr, d_addr, e_addr, x_addr, s_addr = (0x400000 + 0x10 * i for i in range(7))
        h = cond_block(h_addr, 8, b_addr, d_addr)
        b = cond_block(b_addr, 12, c_addr, x_addr)
        c = cond_block(c_addr, 16, h_addr, e_addr)
        d = cond_block(d_addr, 20, h_addr, e_addr)
        e = goto_block(e_addr, s_addr)
        x = goto_block(x_addr, s_addr)
        s = Block(s_addr, 4, statements=[Return(manager.next_atom(), [const(0)], ins_addr=s_addr)])
        graph = networkx.DiGraph([(h, b), (h, d), (b, c), (b, x), (c, h), (c, e), (d, h), (d, e), (e, s), (x, s)])
        overlay = OverlayManager(graph)
        region = overlay.root.create_subregion(h, [h, b, c, d, e, x], cyclic=True)

        # no loop schema matches
        with mock.patch.object(PhoenixStructurer, "_match_cyclic_schemas", return_value=False):
            structurer = project.analyses[PhoenixStructurer].prep()(region, ail_manager=manager)

        nodes = [structurer.result] if structurer.result is not None else list(region.graph)
        dangling_continues = []
        gotos_to_head = []

        def handle_continue(node, **kwargs):  # pylint:disable=unused-argument
            dangling_continues.append(node)

        def handle_block(node, **kwargs):  # pylint:disable=unused-argument
            gotos_to_head.extend(
                stmt
                for stmt in node.statements
                if isinstance(stmt, Jump) and isinstance(stmt.target, Const) and stmt.target.value == h_addr
            )

        walker = SequenceWalker(
            handlers={
                ContinueNode: handle_continue,
                # continues inside a loop are fine; no loop is expected here anyway
                LoopNode: lambda node, **kwargs: None,
                Block: handle_block,
            }
        )
        for node in nodes:
            walker.walk(node)

        assert not dangling_continues
        assert gotos_to_head


if __name__ == "__main__":
    unittest.main()
