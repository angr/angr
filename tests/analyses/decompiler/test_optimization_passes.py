#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import unittest

import networkx as nx

import angr
from angr.ailment.manager import Manager
from angr.ailment import Block, Assignment, Register, Const, BinaryOp
from angr.ailment.expression import Call, Convert, UnaryOp
from angr.ailment.statement import Return, Store, ConditionalJump
from angr.analyses.decompiler.optimization_passes import FlipBooleanCmp
from angr.analyses.decompiler.optimization_passes.carry_flag_simplifier import CarryFlagSimplifier
from angr.analyses.decompiler.optimization_passes.overflow_builtin_p_simplifier import (
    OverflowBuiltinPredicateSimplifier,
)
from angr.analyses.decompiler.optimization_passes.overflow_builtin_simplifier import OverflowBuiltinSimplifier
from angr.analyses.decompiler.structuring.structurer_nodes import CodeNode, SequenceNode, ConditionNode

log = logging.getLogger(__name__)
# log.setLevel(logging.DEBUG)


def c(v):
    """Simple AIL Const shorthand"""
    return Const(None, None, v, 32)


def c64(v):
    """Simple 64-bit AIL Const shorthand"""
    return Const(None, None, v, 64)


def r(o):
    """Simple AIL Register shorthand"""
    return Register(None, None, o, 32)


def r64(o):
    """Simple 64-bit AIL Register shorthand"""
    return Register(None, None, o, 64)


class TestFlipBooleanCmp(unittest.TestCase):
    """
    Test FlipBooleanCmp optimization pass.
    """

    def test_type2_store_not_moved(self):
        """
        Ensure that:

            v0 = 123;
            if (v0 <= 1000)
                v0 = 456;
            g_deadbeef = v0;
            return;

        is not mistakenly transformed to:

            v0 = 123;
            if (v0 > 1000) {
                g_deadbeef = v0;
                return;
            }
            v0 = 456;
        """
        flip_size = 1

        block_0 = Block(
            0x400000,
            1,
            [
                Assignment(None, r(0), c(0x123)),
                ConditionalJump(
                    None, BinaryOp(None, "CmpLE", [r(0), c(0x1000)], False), c(0x400023), c(0x400037), ins_addr=0x400001
                ),
            ],
        )
        block_1 = Block(0x400023, 1, [Assignment(None, r(0), c(0x456)) for _ in range(flip_size)])
        block_2 = Block(
            0x400037,
            1,
            [
                Store(None, c(0xDEADBEEF), r(0), 4, "Iend_LE"),  # Must not be moved
                Return(None, []),
            ],
        )

        graph = nx.DiGraph()
        graph.add_edges_from([(block_0, block_1), (block_0, block_2), (block_1, block_2)])

        func = None
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        ri = proj.analyses.RegionIdentifier(func, graph=graph)
        rs = proj.analyses.RecursiveStructurer(ri.region)
        seq = rs.result

        assert isinstance(seq, SequenceNode)
        assert len(seq.nodes) == 3
        assert isinstance(seq.nodes[0], Block)
        assert isinstance(seq.nodes[1], ConditionNode)
        assert isinstance(seq.nodes[2], Block)
        assert isinstance(seq.nodes[2].statements[0], Store)
        assert isinstance(seq.nodes[2].statements[1], Return)

        pre_transform_seq_repr = seq.dbg_repr()
        log.debug("Before:\n%s", pre_transform_seq_repr)

        manager = Manager()
        FlipBooleanCmp(func, manager, flip_size=flip_size, seq=seq, graph=graph)

        post_transform_seq_repr = seq.dbg_repr()
        log.debug("After:\n%s", post_transform_seq_repr)

        assert pre_transform_seq_repr == post_transform_seq_repr


class TestOverflowAndCarrySimplifiers(unittest.TestCase):
    def test_carry_flag_simplifier_rewrites_cfadd(self):
        cf_call = Call(None, "__CFADD__", args=[r64(0), r64(8)], bits=64)
        condition = Convert(None, 64, 8, False, cf_call)
        err_block = Block(0x400010, 0, [Return(None, [c64(0)])])
        seq = SequenceNode(
            0x400000,
            nodes=[ConditionNode(0x400000, None, condition, CodeNode(err_block, 0x400010), false_node=None)],
        )

        out = CarryFlagSimplifier(None, Manager(), seq=seq).out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        assert isinstance(out_cond.condition, Convert)
        cmp_expr = out_cond.condition.operand
        assert isinstance(cmp_expr, BinaryOp)
        assert cmp_expr.op == "CmpLT"
        assert isinstance(cmp_expr.operands[0], BinaryOp)
        assert cmp_expr.operands[0].op == "Add"

    def test_overflow_builtin_predicate_rewrites_ofadd(self):
        of_call = Call(None, "__OFADD__", args=[r64(0), r64(8)], bits=64)
        condition = UnaryOp(None, "Not", Convert(None, 64, 8, False, of_call), bits=8)
        err_block = Block(0x400010, 0, [Return(None, [c64(0)])])
        seq = SequenceNode(
            0x400000,
            nodes=[ConditionNode(0x400000, None, condition, CodeNode(err_block, 0x400010), false_node=None)],
        )

        out = OverflowBuiltinPredicateSimplifier(None, Manager(), seq=seq).out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        assert isinstance(out_cond.condition, UnaryOp)
        assert out_cond.condition.op == "Not"
        converted = out_cond.condition.operand
        assert isinstance(converted, Convert)
        new_call = converted.operand
        assert isinstance(new_call, Call)
        assert new_call.target == "__builtin_add_overflow_p"
        assert new_call.args is not None
        assert len(new_call.args) == 3
        assert isinstance(new_call.args[2], Const)
        assert new_call.args[2].value == 0

    def test_overflow_builtin_simplifier_rewrites_return_pattern(self):
        a = r64(0)
        b = r64(8)
        of_call = Call(None, "__OFADD__", args=[a, b], bits=64)
        err_block = Block(0x400010, 0, [Return(None, [c64(0xFFFFFFFFFFFFFFFF)])])
        add_expr = BinaryOp(None, "Add", [a, b], False, bits=64)
        arith_block = Block(0x400020, 0, [Return(None, [add_expr])])
        seq = SequenceNode(
            0x400000,
            nodes=[
                ConditionNode(0x400000, None, of_call, CodeNode(err_block, 0x400010), false_node=None),
                CodeNode(arith_block, 0x400020),
            ],
        )

        out = OverflowBuiltinSimplifier(None, Manager(), seq=seq).out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        new_call = out_cond.condition
        assert isinstance(new_call, Call)
        assert new_call.target == "__builtin_add_overflow"
        assert new_call.args is not None
        assert len(new_call.args) == 3

        out_return = out.nodes[1].node.statements[0]
        assert isinstance(out_return, Return)
        assert out_return.ret_exprs is not None
        assert not isinstance(out_return.ret_exprs[0], BinaryOp)

    def test_type2_call_not_moved(self):
        """
        Ensure that:

            v0 = 123;
            if (v0 <= 1000)
                v0 = 456;
            always_called(v0);
            return;

        is not mistakenly transformed to:

            v0 = 123;
            if (v0 > 1000) {
                always_called(v0);
                return;
            }
            v0 = 456;
        """
        flip_size = 1

        block_0 = Block(
            0x400000,
            1,
            [
                Assignment(None, r(0), c(0x123)),
                ConditionalJump(
                    None, BinaryOp(None, "CmpLE", [r(0), c(0x1000)], False), c(0x400023), c(0x400037), ins_addr=0x400001
                ),
            ],
        )
        block_1 = Block(0x400023, 1, [Assignment(None, r(0), c(0x456)) for _ in range(flip_size)])
        block_2 = Block(
            0x400037,
            1,
            [
                Call(None, "always_called", None, None, [r(0)]),  # Must not be moved
                Return(None, []),
            ],
        )

        graph = nx.DiGraph()
        graph.add_edges_from([(block_0, block_1), (block_0, block_2), (block_1, block_2)])

        func = None
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        ri = proj.analyses.RegionIdentifier(func, graph=graph)
        rs = proj.analyses.RecursiveStructurer(ri.region)
        seq = rs.result

        assert isinstance(seq, SequenceNode)
        assert len(seq.nodes) == 3
        assert isinstance(seq.nodes[0], Block)
        assert isinstance(seq.nodes[1], ConditionNode)
        assert isinstance(seq.nodes[2], Block)
        assert isinstance(seq.nodes[2].statements[0], Call)
        assert isinstance(seq.nodes[2].statements[1], Return)

        pre_transform_seq_repr = seq.dbg_repr()
        log.debug("Before:\n%s", pre_transform_seq_repr)

        manager = Manager()
        FlipBooleanCmp(func, manager, flip_size=flip_size, seq=seq, graph=graph)

        post_transform_seq_repr = seq.dbg_repr()
        log.debug("After:\n%s", post_transform_seq_repr)

        assert pre_transform_seq_repr == post_transform_seq_repr
