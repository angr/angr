#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import BinaryOp, Call, Const, Convert, Load, Register
from angr.ailment.statement import Jump, Return, SideEffectStatement
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.structurer_nodes import IncompleteSwitchCaseNode, SequenceNode, SwitchCaseNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer
from angr.analyses.decompiler.structuring.sailr import SAILRStructurer
from angr.analyses.decompiler.utils import sequence_to_blocks
from angr.knowledge_plugins.cfg import IndirectJump, IndirectJumpType


class TestNestedSwitches(unittest.TestCase):
    def test_nested_boolean_dispatch_preserves_cases(self):
        for strategy in (SAILRStructurer, PhoenixStructurer):
            for duplicate_entries in (False, True):
                with self.subTest(strategy=strategy.NAME, duplicate_entries=duplicate_entries):
                    self._check_nested_dispatch(strategy, duplicate_entries)

    def _check_nested_dispatch(self, strategy, duplicate_entries):
        project = angr.load_shellcode(b"\xc3", arch="x86", load_address=0x400000)
        manager = Manager()

        def constant(value):
            return Const(manager.next_atom(), value, 32)

        def dispatch(addr, index, table):
            offset = BinaryOp(manager.next_atom(), "Mul", [index, constant(4)], False, bits=32)
            address = BinaryOp(manager.next_atom(), "Add", [offset, constant(table)], False, bits=32)
            return Block(
                addr,
                4,
                statements=[Jump(manager.next_atom(), Load(manager.next_atom(), address, 4, "Iend_LE"), ins_addr=addr)],
            )

        outer_index = BinaryOp(
            manager.next_atom(),
            "And",
            [Call(manager.next_atom(), constant(0x500000), args=[], bits=32), constant(3 if duplicate_entries else 1)],
            False,
            bits=32,
        )
        outer = dispatch(0x400000, outer_index, 0x600000)
        first = Block(0x400010, 4, statements=[Return(manager.next_atom(), [constant(10)])])
        entry = Block(
            0x400020,
            4,
            statements=[
                SideEffectStatement(
                    manager.next_atom(), Call(manager.next_atom(), constant(0x500010), args=[], bits=32)
                )
            ],
        )
        comparison = BinaryOp(manager.next_atom(), "CmpEQ", [Register(manager.next_atom(), 8, 32), constant(0)], False)
        inner = dispatch(0x400030, Convert(manager.next_atom(), 1, 32, False, comparison), 0x600010)
        second = Block(0x400040, 4, statements=[Return(manager.next_atom(), [constant(20)])])
        third = Block(0x400050, 4, statements=[Return(manager.next_atom(), [constant(30)])])
        graph = networkx.DiGraph([(outer, first), (outer, entry), (entry, inner), (inner, second), (inner, third)])
        overlay = OverlayManager(graph)
        overlay.root.head = outer
        tables = {}
        outer_entries = [first.addr, entry.addr] * (2 if duplicate_entries else 1)
        for head, table, targets in ((outer, 0x600000, outer_entries), (inner, 0x600010, [second.addr, third.addr])):
            jump = IndirectJump(head.addr, head.addr, outer.addr, "Ijk_Boring", 0)
            jump.type = IndirectJumpType.Jumptable_AddressLoadedFromMemory
            jump.jumptable = True
            jump.add_jumptable(table, len(targets) * 4, 4, targets, is_primary=True)
            tables[head.addr] = jump
        result = project.analyses[strategy].prep(fail_fast=True)(
            overlay.root,
            jump_tables=tables,
            ail_manager=manager,
        )
        assert result.result is not None
        blocks = sequence_to_blocks(result.result)
        assert sorted(block.addr for block in blocks) == sorted(
            block.addr for block in (outer, first, entry, inner, second, third)
        )
        assert sorted(str(s) for block in blocks for s in block.statements if isinstance(s, Return)) == [
            "Return (10<32>)",
            "Return (20<32>)",
            "Return (30<32>)",
        ]
        assert sum(isinstance(s, SideEffectStatement) for block in blocks for s in block.statements) == 1

        # The unsupported inner comparison stays explicit, while its predecessor may still be absorbed after
        # the outer switch consumes the original case entry.
        incomplete = result.result
        assert isinstance(incomplete, IncompleteSwitchCaseNode)
        assert isinstance(incomplete.head, SequenceNode)
        switches = [node for node in incomplete.head.nodes if isinstance(node, SwitchCaseNode)]
        assert len(switches) == 1
        switch = switches[0]
        assert switch.switch_expr == outer_index
        assert set(switch.cases) == ({(0, 2), (1, 3)} if duplicate_entries else {0, 1})
        marker_case = switch.cases[(1, 3) if duplicate_entries else 1]
        assert sequence_to_blocks(marker_case) == [entry]
        assert sequence_to_blocks(switch.cases[(0, 2) if duplicate_entries else 0]) == [first]
        assert incomplete.cases == [second, third]


if __name__ == "__main__":
    unittest.main()
