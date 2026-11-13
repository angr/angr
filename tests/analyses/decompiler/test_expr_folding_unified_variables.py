#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment import Block
from angr.ailment.expression import BinaryOp, Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.region_simplifiers.expr_folding import InterferenceChecker
from angr.analyses.decompiler.structurer_nodes import SequenceNode
from angr.analyses.decompiler.variable_map import VariableMap

REGS = {"x": 32, "y": 88, "t": 24}


def _interfered(stmts: list[tuple[int, int | tuple[int, ...]]], names: dict[int, str], candidates: set[int]) -> set[int]:
    """
    Run the checker over one block of ``dst = src`` (or ``dst = src0 + src1``) statements.

    :param names: vvar ID -> name of the variable that the vvar is displayed as.
    :return:      The candidates that must not be folded.
    """

    idx = iter(range(1000))

    def vv(vid):
        return VirtualVariable(next(idx), vid, 32, VirtualVariableCategory.REGISTER, oident=REGS[names[vid]])

    block_stmts = []
    for dst, src in stmts:
        if isinstance(src, tuple):
            src_expr = BinaryOp(next(idx), "Add", [vv(src[0]), vv(src[1])], False, bits=32)
        else:
            src_expr = vv(src)
        block_stmts.append(Assignment(next(idx), vv(dst), src_expr))
    seq = SequenceNode(0x1000, nodes=[Block(0x1000, 1, statements=block_stmts)])
    assignments = {s.dst.varid: (s.src, None) for s in block_stmts if s.dst.varid in candidates}
    checker = InterferenceChecker(assignments, {}, seq, VariableMap(), unified_variable=lambda v: names.get(v.varid))
    return checker.interfered_assignments


class TestFoldingUnifiedVariables(unittest.TestCase):
    NAMES = {1: "x", 2: "x", 3: "y", 4: "y", 10: "t"}

    def test_swap_temporary_is_not_folded(self):
        # t = x; x = y; y = t
        assert _interfered([(10, 1), (2, 3), (4, 10)], self.NAMES, {10}) == {10}

    def test_assignment_after_the_use(self):
        # t = x; y = t; x = y
        assert _interfered([(10, 1), (4, 10), (2, 3)], self.NAMES, {10}) == set()

    def test_use_in_the_assignment_itself(self):
        # t = x; x = t + y
        assert _interfered([(10, 1), (2, (10, 3))], self.NAMES, {10}) == set()

    def test_assignment_to_an_unrelated_variable(self):
        # t = x; y = y; y = t
        assert _interfered([(10, 1), (4, 3), (4, 10)], self.NAMES, {10}) == set()

    def test_without_unified_variables(self):
        idx = iter(range(100))
        stmts = [
            Assignment(
                next(idx),
                VirtualVariable(next(idx), dst, 32, VirtualVariableCategory.REGISTER, oident=8),
                VirtualVariable(next(idx), src, 32, VirtualVariableCategory.REGISTER, oident=8),
            )
            for dst, src in [(10, 1), (2, 3), (4, 10)]
        ]
        seq = SequenceNode(0x1000, nodes=[Block(0x1000, 1, statements=stmts)])
        checker = InterferenceChecker({10: (stmts[0].src, None)}, {}, seq, VariableMap())
        assert checker.interfered_assignments == set()


if __name__ == "__main__":
    unittest.main()
