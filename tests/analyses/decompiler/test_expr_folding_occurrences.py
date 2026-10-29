#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment import Block
from angr.ailment.expression import BinaryOp, Call, Const, Convert, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.region_simplifiers.expr_folding import ExpressionCounter
from angr.analyses.decompiler.structurer_nodes import SequenceNode


class TestExpressionCounterOccurrences(unittest.TestCase):
    def test_identical_copies_are_counted(self):
        m = Manager()
        ret = VirtualVariable(m.next_atom(), 1, 32, VirtualVariableCategory.REGISTER, oident=8)
        out = VirtualVariable(m.next_atom(), 2, 32, VirtualVariableCategory.REGISTER, oident=12)
        use = VirtualVariable(m.next_atom(), 1, 32, VirtualVariableCategory.REGISTER, oident=8)
        # the same vvar expression, at the same operand index of two parents: one (expr, location) pair, two reads
        low = Convert(m.next_atom(), 32, 8, False, use)
        src = BinaryOp(m.next_atom(), "Xor", [low, BinaryOp(m.next_atom(), "Shr", [low, Const(m.next_atom(), 4, 8)], False, bits=8)], False, bits=8)
        block = Block(0x1000, 2, statements=[
            Assignment(m.next_atom(), ret, Call(m.next_atom(), "f", args=[], bits=32)),
            Assignment(m.next_atom(), out, Convert(m.next_atom(), 8, 32, False, src)),
        ])
        counter = ExpressionCounter(SequenceNode(0x1000, nodes=[block]))
        assert len(counter.all_uses[1]) == 1
        assert counter.use_occurrences[1] == 2


if __name__ == "__main__":
    unittest.main()
