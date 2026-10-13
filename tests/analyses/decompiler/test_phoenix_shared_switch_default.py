#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import BinaryOp, Call, Const, Load, Register
from angr.ailment.statement import ConditionalJump, Jump, Return, SideEffectStatement
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structurer_nodes import SwitchCaseNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer
from angr.analyses.decompiler.utils import sequence_to_blocks
from angr.knowledge_plugins.cfg import IndirectJump, IndirectJumpType


class TestPhoenixSharedSwitchDefault(unittest.TestCase):
    def test_two_switches_sharing_the_if_else_merge_point_as_default(self):
        # if (c) { switch (x) { case 0: return 10; case 1: return 20; } } else { switch (x) { case 0: f(); break;
        # case 1: g(); break; } return 30; } T: h(); return 0;
        # both switches use T, the merge point of the if-else, as their default target. absorbing T into the switch
        # that is structured first dropped the other switch's default edge, which lost T (or the whole region).
        project = angr.load_shellcode(b"\xc3", arch="x86", load_address=0x400000)
        manager = Manager()

        def constant(value):
            return Const(manager.next_atom(), value, 32)

        def call(addr, target):
            return SideEffectStatement(
                manager.next_atom(), Call(manager.next_atom(), constant(target), args=[], bits=32), ins_addr=addr
            )

        def ret(addr, value):
            return Block(addr, 4, statements=[Return(manager.next_atom(), [constant(value)], ins_addr=addr)])

        index = Register(manager.next_atom(), 8, 32)

        def bounds_check(addr, dispatch_addr, default_addr):
            cond = BinaryOp(manager.next_atom(), "CmpLE", [index, constant(1)], False, bits=1)
            return Block(
                addr,
                4,
                statements=[
                    ConditionalJump(
                        manager.next_atom(), cond, constant(dispatch_addr), constant(default_addr), ins_addr=addr
                    )
                ],
            )

        def dispatch(addr, table):
            offset = BinaryOp(manager.next_atom(), "Mul", [index, constant(4)], False, bits=32)
            address = BinaryOp(manager.next_atom(), "Add", [offset, constant(table)], False, bits=32)
            return Block(
                addr,
                4,
                statements=[Jump(manager.next_atom(), Load(manager.next_atom(), address, 4, "Iend_LE"), ins_addr=addr)],
            )

        head_cond = BinaryOp(manager.next_atom(), "CmpEQ", [Register(manager.next_atom(), 12, 32), constant(0)], False)
        head = Block(
            0x400000,
            4,
            statements=[
                ConditionalJump(
                    manager.next_atom(), head_cond, constant(0x400010), constant(0x400050), ins_addr=0x400000
                )
            ],
        )
        tail = Block(0x4000A0, 4, statements=[call(0x4000A0, 0x500020), Return(manager.next_atom(), [constant(0)])])
        first_check = bounds_check(0x400010, 0x400020, tail.addr)
        first_dispatch = dispatch(0x400020, 0x600000)
        first_cases = [ret(0x400030, 10), ret(0x400040, 20)]
        second_check = bounds_check(0x400050, 0x400060, tail.addr)
        second_dispatch = dispatch(0x400060, 0x600010)
        merge = ret(0x400090, 30)
        second_cases = [
            Block(
                addr, 4, statements=[call(addr, target), Jump(manager.next_atom(), constant(merge.addr), ins_addr=addr)]
            )
            for addr, target in ((0x400070, 0x500000), (0x400080, 0x500010))
        ]

        graph = networkx.DiGraph(
            [
                (head, first_check),
                (head, second_check),
                (first_check, first_dispatch),
                (first_check, tail),
                (first_dispatch, first_cases[0]),
                (first_dispatch, first_cases[1]),
                (second_check, second_dispatch),
                (second_check, tail),
                (second_dispatch, second_cases[0]),
                (second_dispatch, second_cases[1]),
                (second_cases[0], merge),
                (second_cases[1], merge),
            ]
        )
        # the dispatch nodes are consumed by the switch-case nodes
        expected_blocks = [b for b in graph.nodes if b not in (first_dispatch, second_dispatch)]
        overlay = OverlayManager(graph)
        overlay.root.head = head
        tables = {}
        for check, disp, table, cases in (
            (first_check, first_dispatch, 0x600000, first_cases),
            (second_check, second_dispatch, 0x600010, second_cases),
        ):
            jump = IndirectJump(disp.addr, disp.addr, head.addr, "Ijk_Boring", 0)
            jump.type = IndirectJumpType.Jumptable_AddressLoadedFromMemory
            jump.jumptable = True
            jump.add_jumptable(table, len(cases) * 4, 4, [c.addr for c in cases], is_primary=True)
            tables[disp.addr] = jump
            tables[check.addr] = jump

        result = project.analyses[PhoenixStructurer].prep(fail_fast=True)(
            overlay.root, jump_tables=tables, ail_manager=manager
        )
        assert result.result is not None

        blocks = sequence_to_blocks(result.result)
        missing = [hex(b.addr) for b in expected_blocks if b not in blocks]
        assert not missing, missing
        # the tail is emitted once; the other switch reaches it through a goto in its default case
        assert blocks.count(tail) == 1
        gotos_to_tail = [
            s
            for block in blocks
            for s in block.statements
            if isinstance(s, Jump) and isinstance(s.target, Const) and s.target.value == tail.addr
        ]
        assert len(gotos_to_tail) == 1

        switches: list[SwitchCaseNode] = []

        def handle_switch(node, **kwargs):
            switches.append(node)
            return walker._handle_SwitchCase(node, **kwargs)  # pylint:disable=protected-access

        walker = SequenceWalker(handlers={SwitchCaseNode: handle_switch})
        walker.walk(result.result)
        assert len(switches) == 2
        assert all(switch.default_node is not None for switch in switches)


if __name__ == "__main__":
    unittest.main()
