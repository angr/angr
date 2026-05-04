from __future__ import annotations

from collections import OrderedDict

from angr.ailment import AILBlockRewriter, AILBlockWalker, Block
from angr.ailment.expression import (
    Array,
    ComboRegister,
    Const,
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
    def __init__(self):
        super().__init__()
        self.seen = []

    def _top(self, _expr_idx: int, expr: Expression, _stmt_idx: int, _stmt: Statement | None, _block: Block | None):
        self.seen.append(type(expr).__name__)

    def _stmt_top(self, _stmt_idx: int, stmt: Statement, _block: Block | None):
        self.seen.append(type(stmt).__name__)

    def _handle_block_end(self, _stmt_results: list[None], _block: Block):
        return self.seen


class ConstIncrementingRewriter(AILBlockRewriter):
    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if expr.value == 1:
            return Const(expr.idx, expr.variable, 2, expr.bits, **expr.tags)
        return super()._handle_Const(expr_idx, expr, stmt_idx, stmt, block)


def test_block_walker_visits_rust_ail_expression_children():
    reg0 = Register(0, None, 16, 64)
    reg1 = Register(1, None, 24, 64)
    combo = ComboRegister(2, None, [reg0, reg1])
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
    old_const = Const(0, None, 1, 32)
    struct = Struct(1, "One", OrderedDict([(0, old_const)]), OrderedDict([("value", 0)]), 32)
    enum = RustEnum(2, "Some", [struct], 32)
    array = Array(3, [enum], 32)
    macro = FunctionLikeMacro(4, "dbg", [array], bits=32)
    dst = VirtualVariable(5, 2, 32, VirtualVariableCategory.REGISTER, 16)
    block = Block(0x400010, 0, statements=[Assignment(6, dst, macro)])

    new_block = ConstIncrementingRewriter(update_block=False).walk(block)
    new_macro = new_block.statements[0].src
    new_array = new_macro.args[0]
    new_enum = new_array.elements[0]
    new_struct = new_enum.fields[0]

    assert block.statements[0].src is macro
    assert new_macro is not macro
    assert new_array is not array
    assert new_enum is not enum
    assert new_struct is not struct
    assert new_struct.fields[0].value == 2
