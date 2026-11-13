#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment import Block
from angr.ailment.expression import BinaryOp, Call, Const, Load, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.analyses.decompiler.region_simplifiers.expr_folding import InterferenceChecker
from angr.analyses.decompiler.structurer_nodes import ConditionNode, LoopNode, SequenceNode
from angr.analyses.decompiler.variable_map import VariableMap

REGS = {"x": 32, "y": 88, "t": 24, "i": 40}


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


def _loop_interfered(
    definition: str, body: list, sort: str = "while", use: str = "condition", names: dict[int, str] | None = None
) -> bool:
    """
    Run the checker over ``t = <definition>`` followed by a loop that uses t in its header.

    :param definition: "copy" (t = x), "load" (t = *x), "call" (t = f()), "stack" (t = s, a stack variable), or
                       "stack-addr" (t = &s).
    :param body:       The loop body: (dst, src) for an assignment, "call", "store", or "if-call" (a call in the
                       condition of a nested if).
    :param use:        Where t is used: "condition", "iterator", or "initializer".
    :return:           True if t must not be folded.
    """

    names = names or {1: "x", 2: "x", 3: "y", 4: "y", 5: "i", 6: "i", 10: "t"}
    idx = iter(range(1000))

    def vv(vid):
        return VirtualVariable(next(idx), vid, 64, VirtualVariableCategory.REGISTER, oident=REGS[names[vid]])

    def call(name):
        return Call(next(idx), name, args=[], bits=64)

    def cmp(vid):
        return BinaryOp(next(idx), "CmpNE", [vv(vid), Const(next(idx), 0, 64)], False, bits=1)

    def stack_vv():
        return VirtualVariable(next(idx), 20, 64, VirtualVariableCategory.STACK, oident=-0x10)

    src = {
        "copy": lambda: vv(1),
        "load": lambda: Load(next(idx), vv(1), 8, "Iend_LE"),
        "call": lambda: call("f"),
        "stack": stack_vv,
        "stack-addr": lambda: UnaryOp(next(idx), "Reference", stack_vv(), bits=64),
    }
    def_stmt = Assignment(next(idx), vv(10), src[definition]())

    body_nodes = []
    for item in body:
        if item == "call":
            stmt = SideEffectStatement(next(idx), call("g"))
        elif item == "store":
            stmt = Store(next(idx), vv(3), Const(next(idx), 0, 64), 8, "Iend_LE")
        elif item == "if-call":
            cond = BinaryOp(next(idx), "CmpNE", [call("g"), Const(next(idx), 0, 64)], False, bits=1)
            body_nodes.append(ConditionNode(0x3000, None, cond, Block(0x3000, 1, statements=[])))
            continue
        else:
            stmt = Assignment(next(idx), vv(item[0]), vv(item[1]))
        body_nodes.append(Block(0x2000 + len(body_nodes), 1, statements=[stmt]))

    used = 10
    loop = LoopNode(
        sort,
        cmp(used if use == "condition" else 5),
        SequenceNode(0x2000, nodes=body_nodes),
        addr=0x2000,
        initializer=Assignment(next(idx), vv(6), vv(used)) if use == "initializer" else None,
        iterator=Assignment(next(idx), vv(6), vv(used)) if use == "iterator" else None,
    )
    seq = SequenceNode(0x1000, nodes=[Block(0x1000, 1, statements=[def_stmt]), loop])
    checker = InterferenceChecker(
        {10: (def_stmt.src, None)}, {}, seq, VariableMap(), unified_variable=lambda v: names.get(v.varid)
    )
    return 10 in checker.interfered_assignments


class TestFoldingLoopHeaders(unittest.TestCase):
    def test_variable_assigned_in_the_body(self):
        # t = x; while (t) { x = y; }
        for sort in ("while", "do-while"):
            assert _loop_interfered("copy", [(2, 3)], sort=sort)
        assert _loop_interfered("copy", [(2, 3)], sort="for", use="iterator")

    def test_unrelated_body(self):
        # t = x; while (t) { y = y; g(); *y = 0; }
        for sort in ("while", "do-while"):
            assert not _loop_interfered("copy", [(4, 3), "call", "store"], sort=sort)
        assert not _loop_interfered("copy", [(4, 3), "call", "store"], sort="for", use="iterator")

    def test_call_is_not_folded_into_a_header(self):
        # t = f(); while (t) { }
        for sort in ("while", "do-while"):
            assert _loop_interfered("call", [], sort=sort)
        assert _loop_interfered("call", [], sort="for", use="iterator")

    def test_load_with_memory_writes_in_the_body(self):
        # t = *x; while (t) { g(); }
        for sort in ("while", "do-while"):
            assert _loop_interfered("load", ["call"], sort=sort)
            assert _loop_interfered("load", ["store"], sort=sort)
            assert _loop_interfered("load", ["if-call"], sort=sort)
            assert not _loop_interfered("load", [(4, 3)], sort=sort)

    def test_stack_variable_with_memory_writes_in_the_body(self):
        # t = s; while (t) { g(); }, where s is a stack variable that may be changed through its address
        for sort in ("while", "do-while"):
            assert _loop_interfered("stack", ["call"], sort=sort)
            assert _loop_interfered("stack", ["store"], sort=sort)
            assert not _loop_interfered("stack", [(4, 3)], sort=sort)
            # the address of s does not change
            assert not _loop_interfered("stack-addr", ["call", "store"], sort=sort)

    def test_initializer_is_evaluated_once(self):
        # t = f(); for (i = t; i; ) { x = y; g(); }
        for definition in ("copy", "call"):
            assert not _loop_interfered(definition, [(2, 3), "call"], sort="for", use="initializer")


if __name__ == "__main__":
    unittest.main()
