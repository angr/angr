#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Call, Const, Phi, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Jump
from angr.analyses.decompiler.optimization_passes.duplicate_branch_merger import merge_duplicate_branches

BRANCH, ARM_T, ARM_F, JOIN = 0x400000, 0x400010, 0x400020, 0x400030


def _vvar(varid: int, bits: int = 32) -> VirtualVariable:
    return VirtualVariable(varid, varid, bits, VirtualVariableCategory.REGISTER, oident=16)


def _const(value: int, bits: int = 64) -> Const:
    return Const(None, value, bits)


def _cond():
    """A pure opaque predicate, shaped like what the ccall rewriter emits."""
    return Call(None, "__CFADD__", args=[_vvar(1), _const(239, 8)], bits=1)


def _graph(true_stmts, false_stmts, join_stmts, condition=None):
    """branch -> {true arm, false arm} -> join, with the given statement lists."""
    branch = Block(
        BRANCH,
        1,
        statements=[
            ConditionalJump(None, condition if condition is not None else _cond(), _const(ARM_T), _const(ARM_F))
        ],
    )
    arms = {}
    for addr, stmts in ((ARM_T, true_stmts), (ARM_F, false_stmts)):
        arms[addr] = Block(addr, 1, statements=[*stmts, Jump(None, _const(JOIN))])
    join = Block(JOIN, 1, statements=list(join_stmts))

    graph = networkx.DiGraph()
    graph.add_edge(branch, arms[ARM_T])
    graph.add_edge(branch, arms[ARM_F])
    graph.add_edge(arms[ARM_T], join)
    graph.add_edge(arms[ARM_F], join)
    return graph, branch, arms[ARM_T], arms[ARM_F], join


def _phi(dst_varid: int, true_varid: int, false_varid: int) -> Assignment:
    return Assignment(
        None,
        _vvar(dst_varid),
        Phi(None, 32, [((ARM_T, None), _vvar(true_varid)), ((ARM_F, None), _vvar(false_varid))]),
    )


class TestDuplicateBranchMerger(unittest.TestCase):
    def test_merges_arms_that_differ_only_in_their_destinations(self):
        # both arms compute vvar_1 + 1; only the destination vvar differs
        add = lambda dst: Assignment(None, _vvar(dst), BinaryOp(None, "Add", (_vvar(1), _const(1, 32)), False))
        graph, branch, arm_t, arm_f, join = _graph([add(10)], [add(11)], [_phi(20, 10, 11)])

        assert merge_duplicate_branches(graph) is True
        assert arm_f not in graph
        assert arm_t in graph
        assert isinstance(branch.statements[-1], Jump)
        assert branch.statements[-1].target.value == ARM_T
        # the phi had one incoming value left, so it became a plain copy
        assert isinstance(join.statements[0].src, VirtualVariable)
        assert join.statements[0].src.varid == 10

    def test_refuses_when_a_phi_selects_between_the_arms(self):
        # if (c) x = a; else x = b;  -- the arms really do differ, even though both are one copy
        graph, branch, _, arm_f, _ = _graph(
            [Assignment(None, _vvar(10), _vvar(2))],
            [Assignment(None, _vvar(11), _vvar(3))],
            [_phi(20, 10, 11)],
        )
        assert merge_duplicate_branches(graph) is False
        assert arm_f in graph
        assert isinstance(branch.statements[-1], ConditionalJump)

    def test_refuses_when_the_arms_carry_a_call(self):
        call = lambda dst: Assignment(None, _vvar(dst), Call(None, _const(0x500000), bits=32))
        graph, _, _, arm_f, _ = _graph([call(10)], [call(11)], [_phi(20, 10, 11)])
        assert merge_duplicate_branches(graph) is False
        assert arm_f in graph

    def test_refuses_when_a_dropped_vvar_is_read_elsewhere(self):
        copy = lambda dst: Assignment(None, _vvar(dst), _vvar(1))
        graph, _, _, arm_f, _ = _graph(
            [copy(10)],
            [copy(11)],
            # both arms' definitions are read outside the phi, so dropping either would leave a
            # dangling reference and neither orientation is allowed
            [
                _phi(20, 10, 11),
                Assignment(None, _vvar(21), _vvar(10)),
                Assignment(None, _vvar(22), _vvar(11)),
            ],
        )
        assert merge_duplicate_branches(graph) is False
        assert arm_f in graph

    def test_respects_the_statement_cap(self):
        stmts = lambda base: [Assignment(None, _vvar(base + i), _vvar(1)) for i in range(3)]
        for cap, expected in ((2, False), (3, True)):
            graph, _, _, arm_f, _ = _graph(stmts(10), stmts(20), [_phi(30, 12, 22)])
            assert merge_duplicate_branches(graph, cap) is expected
            assert (arm_f in graph) is not expected

    def test_empty_arms_merge(self):
        graph, branch, arm_t, arm_f, _ = _graph([], [], [])
        assert merge_duplicate_branches(graph) is True
        assert arm_f not in graph
        assert arm_t in graph
        assert isinstance(branch.statements[-1], Jump)

    def test_drops_a_conditional_jump_whose_arms_are_the_same_block(self):
        join = Block(JOIN, 1, statements=[])
        branch = Block(BRANCH, 1, statements=[ConditionalJump(None, _cond(), _const(JOIN), _const(JOIN))])
        graph = networkx.DiGraph()
        graph.add_edge(branch, join)

        assert merge_duplicate_branches(graph) is True
        assert isinstance(branch.statements[-1], Jump)
        assert branch.statements[-1].target.value == JOIN

    def test_keeps_a_conditional_jump_whose_condition_is_impure(self):
        join = Block(JOIN, 1, statements=[])
        impure = Call(None, _const(0x500000), bits=1)
        branch = Block(BRANCH, 1, statements=[ConditionalJump(None, impure, _const(JOIN), _const(JOIN))])
        graph = networkx.DiGraph()
        graph.add_edge(branch, join)

        assert merge_duplicate_branches(graph) is False
        assert isinstance(branch.statements[-1], ConditionalJump)


if __name__ == "__main__":
    unittest.main()
