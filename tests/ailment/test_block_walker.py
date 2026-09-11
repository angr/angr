from __future__ import annotations

import unittest
from collections import OrderedDict
from typing import Any, cast

from angr.ailment import AILBlockRewriter, AILBlockViewer, AILBlockWalker, Block
from angr.ailment.expression import (
    Array,
    ComboRegister,
    Const,
    DirtyExpression,
    Expression,
    FunctionLikeMacro,
    Register,
    RustEnum,
    Struct,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, Statement


class RecordingWalker(AILBlockWalker[None, None, list[str]]):
    """Record visited expression and statement class names."""

    def __init__(self):
        super().__init__()
        self.seen = []

    def _top(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        del expr_idx, stmt_idx, stmt, block
        kind = getattr(expr, "kind", None)
        self.seen.append(kind.name if kind is not None else type(expr).__name__)

    def _stmt_top(self, stmt_idx: int, stmt: Statement, block: Block | None):
        del stmt_idx, block
        kind = getattr(stmt, "kind", None)
        self.seen.append(kind.name if kind is not None else type(stmt).__name__)

    def _handle_block_end(self, stmt_results: list[None], block: Block):
        del stmt_results, block
        return self.seen


class ConstIncrementingRewriter(AILBlockRewriter):
    """Rewrite integer constants with value 1 to value 2."""

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if expr.value == 1:
            return Const(expr.idx, 2, expr.bits, **expr.tags)
        return super()._handle_Const(expr_idx, expr, stmt_idx, stmt, block)


class _RecordingDirtyWalker(AILBlockWalker[None, None, None]):
    def __init__(self):
        super().__init__()
        self.const_slots = []

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self.const_slots.append((expr.value, expr_idx))
        return super()._handle_Const(expr_idx, expr, stmt_idx, stmt, block)

    def _top(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        return None

    def _stmt_top(self, stmt_idx: int, stmt: Statement, block: Block | None):
        return None

    def _handle_block_end(self, stmt_results: list[None], block: Block):
        return None


class _RecordingDirtyViewer(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.const_slots = []

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self.const_slots.append((expr.value, expr_idx))
        return super()._handle_Const(expr_idx, expr, stmt_idx, stmt, block)


class _RecordingDirtyRewriter(AILBlockRewriter):
    def __init__(self):
        super().__init__()
        self.const_slots = []

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self.const_slots.append((expr.value, expr_idx))
        return super()._handle_Const(expr_idx, expr, stmt_idx, stmt, block)


class _ReplacingDirtyRewriter(AILBlockRewriter):
    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        replacements = {0x100: 0x101, 0x300: 0x301}
        if expr.value in replacements:
            return Const(expr.idx, replacements[expr.value], expr.bits, **expr.tags)
        return super()._handle_Const(expr_idx, expr, stmt_idx, stmt, block)


class _EquivalentConstRewriter(AILBlockRewriter):
    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        return Const(expr.idx, expr.value, expr.bits, **expr.tags)


class TestDirtyExpressionWalking(unittest.TestCase):
    """Tests traversal and rebuilding of DirtyExpression children."""

    @staticmethod
    def _dirty_expression() -> DirtyExpression:
        return DirtyExpression(
            5,
            "helper",
            [Const(0, 0x100, 64), Const(1, 0x101, 64)],
            guard=Const(2, 0x200, 1),
            mfx="Ifx_Modify",
            maddr=Const(3, 0x300, 64),
            msize=8,
            bits=64,
            ins_addr=0x400000,
        )

    def test_walkers_use_consistent_child_slots(self):
        dirty = self._dirty_expression()
        expected = [(0x100, 0), (0x101, 1), (0x200, 3), (0x300, 4)]

        for walker_cls in (_RecordingDirtyWalker, _RecordingDirtyViewer, _RecordingDirtyRewriter):
            with self.subTest(walker=walker_cls.__name__):
                walker = walker_cls()
                walker.walk_expression(dirty)
                self.assertEqual(walker.const_slots, expected)

    def test_rewriter_preserves_guard_and_rewrites_memory_address(self):
        dirty = self._dirty_expression()
        rewritten = _ReplacingDirtyRewriter(update_block=False).walk_expression(dirty)

        self.assertIsInstance(rewritten, DirtyExpression)
        rewritten_dirty = cast(Any, rewritten)
        self.assertEqual([operand.value for operand in rewritten_dirty.operands], [0x101, 0x101])
        self.assertEqual(rewritten_dirty.guard, dirty.guard)
        self.assertEqual(rewritten_dirty.maddr.value, 0x301)
        self.assertEqual(rewritten_dirty.callee, dirty.callee)
        self.assertEqual(rewritten_dirty.mfx, dirty.mfx)
        self.assertEqual(rewritten_dirty.msize, dirty.msize)
        self.assertEqual(rewritten_dirty.bits, dirty.bits)
        self.assertEqual(rewritten_dirty.tags, dirty.tags)

    def test_rewriter_compares_rebuilt_children_by_value(self):
        dirty = self._dirty_expression()
        rewritten = _EquivalentConstRewriter(update_block=False).walk_expression(dirty)

        self.assertIs(rewritten, dirty)


def test_block_walker_visits_rust_ail_expression_children():
    reg0 = Register(0, 16, 64)
    reg1 = Register(1, 24, 64)
    combo = ComboRegister(2, [reg0, reg1])
    struct = Struct(3, "Pair", OrderedDict([(0, combo)]), OrderedDict([("value", 0)]), 128)
    enum = RustEnum(4, "Ok", [struct], 128)
    array = Array(5, [enum], 128)
    macro = FunctionLikeMacro(6, "format", [array], bits=128)
    dst = VirtualVariable(7, 1, 128, VirtualVariableCategory.REGISTER, 16)
    block = Block(0x400000, 0, statements=[Assignment(8, dst, macro)])

    seen = RecordingWalker().walk(block)

    assert "FunctionLikeMacro" in seen
    assert "Array" in seen
    assert "RustEnum" in seen
    assert "Struct" in seen
    assert "ComboRegister" in seen
    assert seen.count("Register") == 2


def test_block_rewriter_rebuilds_rust_ail_expression_containers():
    old_const = Const(0, 1, 32)
    struct = Struct(1, "One", OrderedDict([(0, old_const)]), OrderedDict([("value", 0)]), 32)
    enum = RustEnum(2, "Some", [struct], 32)
    array = Array(3, [enum], 32)
    macro = FunctionLikeMacro(4, "dbg", [array], bits=32)
    dst = VirtualVariable(5, 2, 32, VirtualVariableCategory.REGISTER, 16)
    block = Block(0x400010, 0, statements=[Assignment(6, dst, macro)])

    new_block = ConstIncrementingRewriter(update_block=False).walk(block)
    old_stmt = block.statements[0]
    new_stmt = new_block.statements[0]
    assert isinstance(old_stmt, Assignment)
    assert isinstance(new_stmt, Assignment)

    new_macro = new_stmt.src
    assert isinstance(new_macro, FunctionLikeMacro)
    new_array = new_macro.args[0]
    assert isinstance(new_array, Array)
    new_enum = new_array.elements[0]
    assert isinstance(new_enum, RustEnum)
    new_struct = new_enum.fields[0]
    assert isinstance(new_struct, Struct)

    assert old_stmt.src.likes(macro)
    assert not new_macro.likes(macro)
    assert not new_array.likes(array)
    assert not new_enum.likes(enum)
    assert not new_struct.likes(struct)
    assert new_struct.fields[0].value == 2
