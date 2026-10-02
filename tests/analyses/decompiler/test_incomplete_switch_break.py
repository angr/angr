#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import Const, Register
from angr.ailment.statement import Assignment, Jump
from angr.analyses.decompiler.structurer_nodes import BreakNode, IncompleteSwitchCaseNode, SequenceNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer


def _flatten_sequence(node):
    if isinstance(node, SequenceNode):
        for child in node.nodes:
            yield from _flatten_sequence(child)
    else:
        yield node


class TestIncompleteSwitchBreak(unittest.TestCase):
    def test_break_rewrite_preserves_child_label(self):
        for label in ("case", "default"):
            with self.subTest(label=label):
                manager = Manager()
                exit_addr = 0x300
                assignment = Assignment(
                    manager.next_atom(),
                    Register(manager.next_atom(), 0, 64),
                    Const(manager.next_atom(), 1, 64),
                    ins_addr=0x110,
                )
                block = Block(
                    0x110,
                    8,
                    statements=[
                        assignment,
                        Jump(
                            manager.next_atom(),
                            Const(manager.next_atom(), exit_addr, 64),
                            ins_addr=0x114,
                        ),
                    ],
                )
                incomplete_switch = IncompleteSwitchCaseNode(
                    0x100,
                    block if label == "default" else None,
                    [block] if label == "case" else [],
                )
                sequence = SequenceNode(0x100, nodes=[incomplete_switch])

                structurer = object.__new__(PhoenixStructurer)
                structurer._rewrite_conditional_jumps_to_breaks(sequence, [exit_addr])

                child = incomplete_switch.cases[0] if label == "case" else incomplete_switch.head
                assert isinstance(child, SequenceNode)
                flattened = list(_flatten_sequence(child))
                assert flattened[0] is block
                assert not flattened[0].statements
                assert flattened[1].statements == [assignment]
                assert isinstance(flattened[2], BreakNode)
                assert flattened[2].target == exit_addr


if __name__ == "__main__":
    unittest.main()
