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
            ConditionalJump(
                None, condition if condition is not None else _cond(), _const(ARM_T), _const(ARM_F)
            )
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
        Phi(None, 32, [((ARM_T, 0), _vvar(true_varid)), ((ARM_F, 0), _vvar(false_varid))]),
    )


class TestDuplicateBranchMerger(unittest.TestCase):
    def test_merges_arms_that_differ_only_in_their_destinations(self):
        # both arms compute vvar_1 + 1; only the destination vvar differs
        add = lambda dst: Assignment(  # noqa: E731
            None, _vvar(dst), BinaryOp(None, "Add", (_vvar(1), _const(1, 32)), False)
        )
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
        call = lambda dst: Assignment(None, _vvar(dst), Call(None, _const(0x500000), bits=32))  # noqa: E731
        graph, _, _, arm_f, _ = _graph([call(10)], [call(11)], [_phi(20, 10, 11)])
        assert merge_duplicate_branches(graph) is False
        assert arm_f in graph

    def test_refuses_when_a_dropped_vvar_is_read_elsewhere(self):
        copy = lambda dst: Assignment(None, _vvar(dst), _vvar(1))  # noqa: E731
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
        stmts = lambda base: [  # noqa: E731
            Assignment(None, _vvar(base + i), _vvar(1)) for i in range(3)
        ]
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
        branch = Block(
            BRANCH, 1, statements=[ConditionalJump(None, _cond(), _const(JOIN), _const(JOIN))]
        )
        graph = networkx.DiGraph()
        graph.add_edge(branch, join)

        assert merge_duplicate_branches(graph) is True
        assert isinstance(branch.statements[-1], Jump)
        assert branch.statements[-1].target.value == JOIN

    def test_keeps_a_conditional_jump_whose_condition_is_impure(self):
        join = Block(JOIN, 1, statements=[])
        impure = Call(None, _const(0x500000), bits=1)
        branch = Block(
            BRANCH, 1, statements=[ConditionalJump(None, impure, _const(JOIN), _const(JOIN))]
        )
        graph = networkx.DiGraph()
        graph.add_edge(branch, join)

        assert merge_duplicate_branches(graph) is False
        assert isinstance(branch.statements[-1], ConditionalJump)


P1, P2, TWIN_X, TWIN_Y, TWIN_J = 0x401000, 0x401010, 0x401020, 0x401030, 0x401040


def _phi_at(dst_varid: int, *entries) -> Assignment:
    return Assignment(
        None, _vvar(dst_varid), Phi(None, 32, [((addr, 0), _vvar(varid)) for addr, varid in entries])
    )


def _twin_graph(y_from_p1: int = 100, join_from_y: int = 11):
    """Two branches into the same pair of arms, whose phis only tell the entering branch apart."""
    cjump = lambda varid: ConditionalJump(  # noqa: E731
        None,
        Call(None, "__CFADD__", args=[_vvar(varid), _const(239, 8)], bits=1),
        _const(TWIN_X),
        _const(TWIN_Y),
    )
    p1 = Block(P1, 1, statements=[cjump(1)])
    p2 = Block(P2, 1, statements=[cjump(2)])
    x = Block(TWIN_X, 1, statements=[_phi_at(10, (P1, 100), (P2, 200)), Jump(None, _const(TWIN_J))])
    y = Block(TWIN_Y, 1, statements=[_phi_at(11, (P1, y_from_p1), (P2, 200)), Jump(None, _const(TWIN_J))])
    join = Block(TWIN_J, 1, statements=[_phi_at(20, (TWIN_X, 10), (TWIN_Y, join_from_y))])
    graph = networkx.DiGraph()
    for src, dst in ((p1, x), (p1, y), (p2, x), (p2, y), (x, join), (y, join)):
        graph.add_edge(src, dst)
    return graph, p1, p2, x, y, join


class TestTwinArmRedirect(unittest.TestCase):
    def test_redirects_every_branch_and_drops_the_twin(self):
        graph, p1, p2, _, y, join = _twin_graph()

        assert merge_duplicate_branches(graph) is True
        assert y not in graph
        assert isinstance(p1.statements[-1], Jump)
        assert isinstance(p2.statements[-1], Jump)
        # the join's phi lost a source and became a copy
        assert isinstance(join.statements[0].src, VirtualVariable)
        assert join.statements[0].src.varid == 10

    def test_redirects_only_the_branch_whose_phi_values_agree(self):
        graph, p1, p2, _, y, join = _twin_graph(y_from_p1=101)

        assert merge_duplicate_branches(graph) is True
        assert y in graph
        assert isinstance(p1.statements[-1], ConditionalJump)
        assert isinstance(p2.statements[-1], Jump)
        # the surviving arm keeps a phi so later twins still pair
        assert isinstance(y.statements[0].src, Phi)
        assert [vvar.varid for _, vvar in y.statements[0].src.src_and_vvars] == [101]
        assert isinstance(join.statements[0].src, Phi)

    def test_keeps_arms_the_join_tells_apart(self):
        graph, p1, p2, _, y, _ = _twin_graph(join_from_y=300)

        assert merge_duplicate_branches(graph) is False
        assert y in graph
        assert isinstance(p1.statements[-1], ConditionalJump)
        assert isinstance(p2.statements[-1], ConditionalJump)

    def test_collapses_an_empty_lattice(self):
        top, mid_a, mid_b, low_a, low_b, end = (0x402000 + 0x10 * i for i in range(6))
        cjump = lambda varid, t, f: ConditionalJump(  # noqa: E731
            None, Call(None, "__CFADD__", args=[_vvar(varid), _const(239, 8)], bits=1), _const(t), _const(f)
        )
        blocks = {
            top: Block(top, 1, statements=[cjump(1, mid_a, mid_b)]),
            mid_a: Block(mid_a, 1, statements=[cjump(2, low_a, low_b)]),
            mid_b: Block(mid_b, 1, statements=[cjump(2, low_a, low_b)]),
            low_a: Block(low_a, 1, statements=[Jump(None, _const(end))]),
            low_b: Block(low_b, 1, statements=[Jump(None, _const(end))]),
            end: Block(end, 1, statements=[_phi_at(30, (low_a, 7), (low_b, 7))]),
        }
        graph = networkx.DiGraph()
        edges = [(top, mid_a), (top, mid_b), (mid_a, low_a), (mid_a, low_b), (mid_b, low_a), (mid_b, low_b)]
        for src, dst in [*edges, (low_a, end), (low_b, end)]:
            graph.add_edge(blocks[src], blocks[dst])

        assert merge_duplicate_branches(graph) is True
        assert len(graph) == 4
        assert all(isinstance(block.statements[-1], Jump) for block in graph if block.addr != end)


if __name__ == "__main__":
    unittest.main()
