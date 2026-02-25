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
from angr.ailment.expression import Call, Convert, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Return, Store, ConditionalJump
from angr.analyses.decompiler.optimization_passes import FlipBooleanCmp
from angr.analyses.decompiler.optimization_passes.overflow_builtin_simplifier import OverflowBuiltinSimplifier
from angr.analyses.decompiler.optimization_passes.overflow_builtin_p_simplifier import (
    OverflowBuiltinPredicateSimplifier,
)
from angr.analyses.decompiler.optimization_passes.carry_flag_simplifier import CarryFlagSimplifier
from angr.analyses.decompiler.structuring.structurer_nodes import SequenceNode, ConditionNode, CodeNode

log = logging.getLogger(__name__)
# log.setLevel(logging.DEBUG)


def c(v):
    """Simple AIL Const shorthand"""
    return Const(None, None, v, 32)


def r(o):
    """Simple AIL Register shorthand"""
    return Register(None, None, o, 32)


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


def _vv(varid, bits=64):
    """Create a VirtualVariable for testing."""
    return VirtualVariable(None, varid, bits, VirtualVariableCategory.UNKNOWN)


def _c64(v):
    """64-bit Const shorthand."""
    return Const(None, None, v, 64)


class TestOverflowBuiltinSimplifier(unittest.TestCase):
    """
    Test OverflowBuiltinSimplifier optimization pass.
    """

    def test_pattern_a_ofadd(self):
        """
        Pattern A (CondO, if-then + fallthrough):

            if (__OFADD__(a, b)) { return 0xffffffffffffffff; }
            return a + b;

        Should become:

            if (__builtin_add_overflow(a, b, &result)) { return 0xffffffffffffffff; }
            return result;
        """
        a = _vv(1)
        b = _vv(2)

        # Build the overflow call condition
        of_call = Call(None, "__OFADD__", args=[a, b], bits=64)

        # Error return block (true branch)
        err_block = Block(0x400010, 0, [Return(None, [_c64(0xFFFFFFFFFFFFFFFF)])])

        # Success return block (fallthrough after the condition)
        add_expr = BinaryOp(None, "Add", [a, b], False, bits=64)
        success_block = Block(0x400020, 0, [Return(None, [add_expr])])

        # Build structured AST
        cond_node = ConditionNode(0x400000, None, of_call, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node, success_block])

        manager = Manager()
        pass_ = OverflowBuiltinSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        # The condition should now be __builtin_add_overflow(a, b, &result)
        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        new_call = out_cond.condition
        assert isinstance(new_call, Call)
        assert new_call.args is not None
        assert new_call.target == "__builtin_add_overflow"
        assert len(new_call.args) == 3
        # First two args should be the original a, b
        assert new_call.args[0].likes(a)
        assert new_call.args[1].likes(b)
        # Third arg should be &result (UnaryOp Reference)
        ref = new_call.args[2]
        assert isinstance(ref, UnaryOp)
        assert ref.op == "Reference"
        result_vvar = ref.operand
        assert isinstance(result_vvar, VirtualVariable)

        # The success return should now use result_vvar instead of a+b
        success_node = out.nodes[1]
        if isinstance(success_node, CodeNode):
            success_node = success_node.node
        assert isinstance(success_node, Block)
        ret_stmt = success_node.statements[0]
        assert isinstance(ret_stmt, Return)
        assert ret_stmt.ret_exprs[0].likes(result_vvar)

    def test_pattern_b_negated_ofadd(self):
        """
        Pattern B (CondNO after FlipBooleanCmp, negated):

            if (!(__OFADD__(a, b))) { return a + b; }
            return 0xffffffffffffffff;

        Should become:

            if (!(__builtin_add_overflow(a, b, &result))) { return result; }
            return 0xffffffffffffffff;
        """
        a = _vv(1)
        b = _vv(2)

        of_call = Call(None, "__OFADD__", args=[a, b], bits=64)
        negated_cond = UnaryOp(None, "Not", of_call, bits=64)

        # Success return in true branch (negated means this is the non-overflow path)
        add_expr = BinaryOp(None, "Add", [a, b], False, bits=64)
        success_block = Block(0x400010, 0, [Return(None, [add_expr])])

        # Error return as fallthrough
        err_block = Block(0x400020, 0, [Return(None, [_c64(0xFFFFFFFFFFFFFFFF)])])

        cond_node = ConditionNode(0x400000, None, negated_cond, true_node=success_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node, err_block])

        manager = Manager()
        pass_ = OverflowBuiltinSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        # The condition should be !(builtin_add_overflow(a, b, &result))
        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        not_expr = out_cond.condition
        assert isinstance(not_expr, UnaryOp)
        assert not_expr.op == "Not"
        new_call = not_expr.operand
        assert isinstance(new_call, Call)
        assert new_call.args is not None
        assert new_call.target == "__builtin_add_overflow"
        assert len(new_call.args) == 3
        ref = new_call.args[2]
        assert isinstance(ref, UnaryOp)
        assert ref.op == "Reference"
        result_vvar = ref.operand
        assert isinstance(result_vvar, VirtualVariable)

        # The true branch return should now use result instead of a+b
        true_block = out_cond.true_node
        if isinstance(true_block, CodeNode):
            true_block = true_block.node
        assert isinstance(true_block, Block)
        ret_stmt = true_block.statements[0]
        assert isinstance(ret_stmt, Return)
        assert ret_stmt.ret_exprs[0].likes(result_vvar)

    def test_pattern_a_ofmul(self):
        """
        Pattern A with __OFMUL__:

            if (__OFMUL__(a, b)) { return 0xffffffffffffffff; }
            return a * b;

        Should become:

            if (__builtin_mul_overflow(a, b, &result)) { return 0xffffffffffffffff; }
            return result;
        """
        a = _vv(1)
        b = _vv(2)

        of_call = Call(None, "__OFMUL__", args=[a, b], bits=64)

        err_block = Block(0x400010, 0, [Return(None, [_c64(0xFFFFFFFFFFFFFFFF)])])
        mul_expr = BinaryOp(None, "Mul", [a, b], False, bits=64)
        success_block = Block(0x400020, 0, [Return(None, [mul_expr])])

        cond_node = ConditionNode(0x400000, None, of_call, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node, success_block])

        manager = Manager()
        pass_ = OverflowBuiltinSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        new_call = out_cond.condition
        assert isinstance(new_call, Call)
        assert new_call.args is not None
        assert new_call.target == "__builtin_mul_overflow"
        assert len(new_call.args) == 3

        # The success return should use result_vvar
        ref = new_call.args[2]
        assert isinstance(ref, UnaryOp)
        result_vvar = ref.operand
        success_node = out.nodes[1]
        if isinstance(success_node, CodeNode):
            success_node = success_node.node
        assert isinstance(success_node, Block)
        ret_stmt = success_node.statements[0]
        assert isinstance(ret_stmt, Return)
        assert ret_stmt.ret_exprs[0].likes(result_vvar)

    def test_pattern_c_if_then_else(self):
        """
        Pattern C (if-then-else):

            if (__OFADD__(a, b)) { return 0xffffffffffffffff; }
            else { return a + b; }

        Should become:

            if (__builtin_add_overflow(a, b, &result)) { return 0xffffffffffffffff; }
            else { return result; }
        """
        a = _vv(1)
        b = _vv(2)

        of_call = Call(None, "__OFADD__", args=[a, b], bits=64)

        err_block = Block(0x400010, 0, [Return(None, [_c64(0xFFFFFFFFFFFFFFFF)])])
        add_expr = BinaryOp(None, "Add", [a, b], False, bits=64)
        success_block = Block(0x400020, 0, [Return(None, [add_expr])])

        cond_node = ConditionNode(0x400000, None, of_call, true_node=err_block, false_node=success_block)
        # Need a dummy next node since the walker looks at pairs
        dummy = Block(0x400030, 0, [Return(None, [])])
        seq = SequenceNode(0x400000, nodes=[cond_node, dummy])

        manager = Manager()
        pass_ = OverflowBuiltinSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        new_call = out_cond.condition
        assert isinstance(new_call, Call)
        assert new_call.args is not None
        assert new_call.target == "__builtin_add_overflow"

        # The false branch return should use result_vvar
        ref = new_call.args[2]
        assert isinstance(ref, UnaryOp)
        result_vvar = ref.operand
        false_block = out_cond.false_node
        if isinstance(false_block, CodeNode):
            false_block = false_block.node
        assert isinstance(false_block, Block)
        ret_stmt = false_block.statements[0]
        assert isinstance(ret_stmt, Return)
        assert ret_stmt.ret_exprs[0].likes(result_vvar)

    def test_no_match_without_arithmetic(self):
        """
        If there's no matching arithmetic in the sibling, the pass should not modify anything.

            if (__OFADD__(a, b)) { return 0xffffffffffffffff; }
            return c;  // no a + b here
        """
        a = _vv(1)
        b = _vv(2)
        other = _vv(3)

        of_call = Call(None, "__OFADD__", args=[a, b], bits=64)
        err_block = Block(0x400010, 0, [Return(None, [_c64(0xFFFFFFFFFFFFFFFF)])])
        # Return something unrelated
        other_block = Block(0x400020, 0, [Return(None, [other])])

        cond_node = ConditionNode(0x400000, None, of_call, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node, other_block])

        manager = Manager()
        pass_ = OverflowBuiltinSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        # Should still get output but condition should be unchanged
        assert out is not None
        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        # Condition should still be the original __OFADD__ call
        assert isinstance(out_cond.condition, Call)
        assert out_cond.condition.target == "__OFADD__"

    def test_convert_wrapped_ofadd(self):
        """
        The condition may be wrapped in a Convert:

            if ((char)__OFADD__(a, b)) { return 0xffffffffffffffff; }
            return a + b;

        Should still be recognized and transformed.
        """
        a = _vv(1)
        b = _vv(2)

        of_call = Call(None, "__OFADD__", args=[a, b], bits=64)
        # Wrap in Convert (e.g., (char) cast)
        converted = Convert(None, 64, 8, False, of_call)

        err_block = Block(0x400010, 0, [Return(None, [_c64(0xFFFFFFFFFFFFFFFF)])])
        add_expr = BinaryOp(None, "Add", [a, b], False, bits=64)
        success_block = Block(0x400020, 0, [Return(None, [add_expr])])

        cond_node = ConditionNode(0x400000, None, converted, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node, success_block])

        manager = Manager()
        pass_ = OverflowBuiltinSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        new_call_convert = out_cond.condition
        assert isinstance(new_call_convert, Call)
        assert new_call_convert.target == "__builtin_add_overflow"

    def test_double_negation_convert_pattern(self):
        """
        Real-world pattern from -O1 cmovno code:

            if (!((char)!(__OFADD__(a, b)))) { return 0xffffffffffffffff; }
            return a + b;

        The double negation cancels out, so this is equivalent to:

            if (__OFADD__(a, b)) { return ERR; }
            return a + b;

        Should become:

            if (__builtin_add_overflow(a, b, &result)) { return 0xffffffffffffffff; }
            return result;
        """
        a = _vv(1)
        b = _vv(2)

        of_call = Call(None, "__OFADD__", args=[a, b], bits=64)
        # !(__OFADD__(...))
        inner_not = UnaryOp(None, "Not", of_call, bits=64)
        # (char)!(__OFADD__(...))
        converted = Convert(None, 64, 8, False, inner_not)
        # !((char)!(__OFADD__(...)))
        outer_not = UnaryOp(None, "Not", converted, bits=8)

        err_block = Block(0x400010, 0, [Return(None, [_c64(0xFFFFFFFFFFFFFFFF)])])
        add_expr = BinaryOp(None, "Add", [a, b], False, bits=64)
        success_block = Block(0x400020, 0, [Return(None, [add_expr])])

        cond_node = ConditionNode(0x400000, None, outer_not, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node, success_block])

        manager = Manager()
        pass_ = OverflowBuiltinSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        # Double negation should cancel: condition is __builtin_add_overflow (no Not wrapper)
        new_call_dblneg = out_cond.condition
        assert isinstance(new_call_dblneg, Call)
        assert new_call_dblneg.args is not None
        assert new_call_dblneg.target == "__builtin_add_overflow"
        assert len(new_call_dblneg.args) == 3

        ref = new_call_dblneg.args[2]
        assert isinstance(ref, UnaryOp)
        result_vvar = ref.operand
        success_node = out.nodes[1]
        if isinstance(success_node, CodeNode):
            success_node = success_node.node
        assert isinstance(success_node, Block)
        ret_stmt = success_node.statements[0]
        assert isinstance(ret_stmt, Return)
        assert ret_stmt.ret_exprs[0].likes(result_vvar)

    def test_single_negation_convert_ofmul(self):
        """
        Real-world pattern from -O1 cmovno code:

            if (!((char)__OFMUL__(a, b))) { return a * b; }
            return 0;

        Should become:

            if (!(__builtin_mul_overflow(a, b, &result))) { return result; }
            return 0;
        """
        a = _vv(1)
        b = _vv(2)

        of_call = Call(None, "__OFMUL__", args=[a, b], bits=64)
        # (char)__OFMUL__(...)
        converted = Convert(None, 64, 8, False, of_call)
        # !((char)__OFMUL__(...))
        negated_cond = UnaryOp(None, "Not", converted, bits=8)

        mul_expr = BinaryOp(None, "Mul", [a, b], False, bits=64)
        success_block = Block(0x400010, 0, [Return(None, [mul_expr])])
        err_block = Block(0x400020, 0, [Return(None, [_c64(0)])])

        cond_node = ConditionNode(0x400000, None, negated_cond, true_node=success_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node, err_block])

        manager = Manager()
        pass_ = OverflowBuiltinSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        # Should be negated: !(__builtin_mul_overflow(...))
        not_expr = out_cond.condition
        assert isinstance(not_expr, UnaryOp)
        assert not_expr.op == "Not"
        new_call_neg = not_expr.operand
        assert isinstance(new_call_neg, Call)
        assert new_call_neg.args is not None
        assert new_call_neg.target == "__builtin_mul_overflow"

        ref = new_call_neg.args[2]
        assert isinstance(ref, UnaryOp)
        result_vvar = ref.operand
        true_block = out_cond.true_node
        if isinstance(true_block, CodeNode):
            true_block = true_block.node
        assert isinstance(true_block, Block)
        ret_stmt = true_block.statements[0]
        assert isinstance(ret_stmt, Return)
        assert ret_stmt.ret_exprs[0].likes(result_vvar)

    def test_mull_widening_multiply(self):
        """
        Unsigned multiply overflow uses Mull (widening multiply) wrapped in Convert:

            if (!(__OFMUL__(a, b))) { return (uint64_t)(a Mull b); }
            return 0;

        Should become:

            if (!(__builtin_mul_overflow(a, b, &result))) { return result; }
            return 0;
        """
        a = _vv(1)
        b = _vv(2)

        of_call = Call(None, "__OFMUL__", args=[a, b], bits=64)
        negated_cond = UnaryOp(None, "Not", of_call, bits=64)

        # Mull (widening multiply) wrapped in Convert(128->64)
        mull_expr = BinaryOp(None, "Mull", [a, b], False, bits=128)
        truncated = Convert(None, 128, 64, False, mull_expr)
        success_block = Block(0x400010, 0, [Return(None, [truncated])])
        err_block = Block(0x400020, 0, [Return(None, [_c64(0)])])

        cond_node = ConditionNode(0x400000, None, negated_cond, true_node=success_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node, err_block])

        manager = Manager()
        pass_ = OverflowBuiltinSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        not_expr = out_cond.condition
        assert isinstance(not_expr, UnaryOp)
        assert not_expr.op == "Not"
        new_call = not_expr.operand
        assert isinstance(new_call, Call)
        assert new_call.args is not None
        assert new_call.target == "__builtin_mul_overflow"

        ref = new_call.args[2]
        assert isinstance(ref, UnaryOp)
        result_vvar = ref.operand
        true_block = out_cond.true_node
        if isinstance(true_block, CodeNode):
            true_block = true_block.node
        assert isinstance(true_block, Block)
        ret_stmt = true_block.statements[0]
        assert isinstance(ret_stmt, Return)
        # The Mull was inside a Convert — result should be wrapped in Convert too
        ret_val = ret_stmt.ret_exprs[0]
        assert isinstance(ret_val, Convert)
        assert ret_val.operand.likes(result_vvar)


class TestOverflowBuiltinPredicateSimplifier(unittest.TestCase):
    """
    Test OverflowBuiltinPredicateSimplifier optimization pass.
    """

    def test_overflow_builtin_p_ofadd(self):
        """
        Standalone __OFADD__ (no paired arithmetic) should become __builtin_add_overflow_p:

            if ((char)__OFADD__(a, b)) { ... }

        becomes:

            if ((char)__builtin_add_overflow_p(a, b, (typeof(a))0)) { ... }
        """
        a = _vv(1)
        b = _vv(2)

        of_call = Call(None, "__OFADD__", args=[a, b], bits=64)
        converted = Convert(None, 64, 8, False, of_call)

        err_block = Block(0x400010, 0, [Return(None, [_c64(0xFFFFFFFFFFFFFFFF)])])
        cond_node = ConditionNode(0x400000, None, converted, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node])

        manager = Manager()
        pass_ = OverflowBuiltinPredicateSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        new_cond = out_cond.condition
        assert isinstance(new_cond, Convert)
        new_call = new_cond.operand
        assert isinstance(new_call, Call)
        assert new_call.target == "__builtin_add_overflow_p"
        assert new_call.args is not None
        assert len(new_call.args) == 3
        assert new_call.args[0].likes(a)
        assert new_call.args[1].likes(b)
        zero_arg = new_call.args[2]
        assert isinstance(zero_arg, Const)
        assert zero_arg.value == 0
        assert zero_arg.bits == a.bits

    def test_overflow_builtin_p_ofmul(self):
        """
        Standalone __OFMUL__ should become __builtin_mul_overflow_p:

            if (__OFMUL__(a, b)) { ... }

        becomes:

            if (__builtin_mul_overflow_p(a, b, (typeof(a))0)) { ... }
        """
        a = _vv(1)
        b = _vv(2)

        of_call = Call(None, "__OFMUL__", args=[a, b], bits=64)

        err_block = Block(0x400010, 0, [Return(None, [_c64(0)])])
        cond_node = ConditionNode(0x400000, None, of_call, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node])

        manager = Manager()
        pass_ = OverflowBuiltinPredicateSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        new_call = out_cond.condition
        assert isinstance(new_call, Call)
        assert new_call.target == "__builtin_mul_overflow_p"
        assert new_call.args is not None
        assert len(new_call.args) == 3
        third_arg = new_call.args[2]
        assert isinstance(third_arg, Const)
        assert third_arg.value == 0

    def test_overflow_builtin_p_negated(self):
        """
        Negated and Convert-wrapped __OFADD__ should be rewritten while
        preserving the Not wrapper:

            if (!((char)__OFADD__(a, b))) { ... }

        becomes:

            if (!((char)__builtin_add_overflow_p(a, b, (typeof(a))0))) { ... }
        """
        a = _vv(1)
        b = _vv(2)

        of_call = Call(None, "__OFADD__", args=[a, b], bits=64)
        converted = Convert(None, 64, 8, False, of_call)
        negated = UnaryOp(None, "Not", converted, bits=8)

        err_block = Block(0x400010, 0, [Return(None, [_c64(0)])])
        cond_node = ConditionNode(0x400000, None, negated, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node])

        manager = Manager()
        pass_ = OverflowBuiltinPredicateSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        # Not wrapping should be preserved
        not_expr = out_cond.condition
        assert isinstance(not_expr, UnaryOp)
        assert not_expr.op == "Not"
        inner_conv = not_expr.operand
        assert isinstance(inner_conv, Convert)
        new_call = inner_conv.operand
        assert isinstance(new_call, Call)
        assert new_call.target == "__builtin_add_overflow_p"
        assert new_call.args is not None
        assert len(new_call.args) == 3

    def test_overflow_builtin_p_ignores_cfadd(self):
        """
        __CFADD__ (carry flag) should NOT be rewritten — there is no _p builtin for it.
        """
        a = _vv(1)
        b = _vv(2)

        cf_call = Call(None, "__CFADD__", args=[a, b], bits=64)

        err_block = Block(0x400010, 0, [Return(None, [_c64(0)])])
        cond_node = ConditionNode(0x400000, None, cf_call, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node])

        manager = Manager()
        pass_ = OverflowBuiltinPredicateSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None
        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        assert isinstance(out_cond.condition, Call)
        assert out_cond.condition.target == "__CFADD__"


class TestCarryFlagSimplifier(unittest.TestCase):
    """
    Test CarryFlagSimplifier optimization pass.
    """

    def test_cfadd_basic(self):
        """
        __CFADD__(a, b) should become (a + b) < a (unsigned):

            if ((char)__CFADD__(a, b)) { ... }

        becomes:

            if ((char)((a + b) < a)) { ... }
        """
        a = _vv(1)
        b = _vv(2)

        cf_call = Call(None, "__CFADD__", args=[a, b], bits=64)
        converted = Convert(None, 64, 8, False, cf_call)

        err_block = Block(0x400010, 0, [Return(None, [_c64(1)])])
        cond_node = ConditionNode(0x400000, None, converted, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node])

        manager = Manager()
        pass_ = CarryFlagSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        # Outer Convert should be preserved
        new_cond = out_cond.condition
        assert isinstance(new_cond, Convert)
        # Inner should be CmpLT (unsigned)
        cmp = new_cond.operand
        assert isinstance(cmp, BinaryOp)
        assert cmp.op == "CmpLT"
        assert cmp.signed is False
        # Left operand: a + b
        add = cmp.operands[0]
        assert isinstance(add, BinaryOp)
        assert add.op == "Add"
        assert add.operands[0].likes(a)
        assert add.operands[1].likes(b)
        # Right operand: a
        assert cmp.operands[1].likes(a)

    def test_cfadd_negated(self):
        """
        Negated __CFADD__ should preserve the Not wrapper:

            if (!((char)__CFADD__(a, b))) { ... }

        becomes:

            if (!((char)((a + b) < a))) { ... }
        """
        a = _vv(1)
        b = _vv(2)

        cf_call = Call(None, "__CFADD__", args=[a, b], bits=64)
        converted = Convert(None, 64, 8, False, cf_call)
        negated = UnaryOp(None, "Not", converted, bits=8)

        err_block = Block(0x400010, 0, [Return(None, [_c64(0)])])
        cond_node = ConditionNode(0x400000, None, negated, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node])

        manager = Manager()
        pass_ = CarryFlagSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None

        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        not_expr = out_cond.condition
        assert isinstance(not_expr, UnaryOp)
        assert not_expr.op == "Not"
        inner_conv = not_expr.operand
        assert isinstance(inner_conv, Convert)
        cmp = inner_conv.operand
        assert isinstance(cmp, BinaryOp)
        assert cmp.op == "CmpLT"
        assert cmp.signed is False

    def test_cfadd_ignores_ofadd(self):
        """
        __OFADD__ should NOT be touched by this pass.
        """
        a = _vv(1)
        b = _vv(2)

        of_call = Call(None, "__OFADD__", args=[a, b], bits=64)

        err_block = Block(0x400010, 0, [Return(None, [_c64(0)])])
        cond_node = ConditionNode(0x400000, None, of_call, true_node=err_block, false_node=None)
        seq = SequenceNode(0x400000, nodes=[cond_node])

        manager = Manager()
        pass_ = CarryFlagSimplifier(None, manager, seq=seq)

        out = pass_.out_seq
        assert out is not None
        out_cond = out.nodes[0]
        assert isinstance(out_cond, ConditionNode)
        assert isinstance(out_cond.condition, Call)
        assert out_cond.condition.target == "__OFADD__"
