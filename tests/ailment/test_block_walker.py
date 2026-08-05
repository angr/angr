from __future__ import annotations

from collections import OrderedDict

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


class RegisterRecordingViewer(AILBlockViewer):
    """Record registers visited by a block viewer."""

    def __init__(self):
        super().__init__()
        self.registers = []

    def _handle_Register(
        self, expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        self.registers.append(expr)
        return super()._handle_Register(expr_idx, expr, stmt_idx, stmt, block)


class ConstIndexRecordingRewriter(AILBlockRewriter):
    """Record constant values and their expression child indices while rewriting."""

    def __init__(self):
        super().__init__(update_block=False)
        self.const_indices = []

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self.const_indices.append((expr.value, expr_idx))
        return super()._handle_Const(expr_idx, expr, stmt_idx, stmt, block)


class ConstIndexRecordingWalker(AILBlockWalker[None, None, None]):
    """Record constant values and their expression child indices while walking."""

    def __init__(self):
        super().__init__()
        self.const_indices = []

    def _top(self, expr_idx, expr, stmt_idx, stmt, block):
        return None

    def _stmt_top(self, stmt_idx, stmt, block):
        return None

    def _handle_block_end(self, stmt_results, block):
        return None

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self.const_indices.append((expr.value, expr_idx))
        return super()._handle_Const(expr_idx, expr, stmt_idx, stmt, block)


class ConstIndexRecordingViewer(AILBlockViewer):
    """Record constant values and their expression child indices while viewing."""

    def __init__(self):
        super().__init__()
        self.const_indices = []

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self.const_indices.append((expr.value, expr_idx))
        return super()._handle_Const(expr_idx, expr, stmt_idx, stmt, block)


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


def test_block_walkers_visit_dirty_memory_address():
    maddr = Register(0, 24, 64)
    dirty = DirtyExpression(
        1,
        "helper",
        [Const(2, 3, 64)],
        guard=Const(3, 1, 1),
        mfx="Ifx_Read",
        maddr=maddr,
        msize=4,
        bits=32,
    )
    dst = VirtualVariable(4, 1, 32, VirtualVariableCategory.REGISTER, 16)
    block = Block(0x400020, 0, statements=[Assignment(5, dst, dirty)])

    seen = RecordingWalker().walk(block)
    assert seen.count("Register") == 1

    viewer = RegisterRecordingViewer()
    viewer.walk(block)
    assert viewer.registers == [maddr]


def test_block_rewriter_updates_dirty_memory_address_without_changing_other_metadata():
    operand = Const(0, 3, 64)
    guard = Const(1, 0, 1)
    maddr = Const(2, 1, 64)
    dirty = DirtyExpression(
        3,
        "load_linked_le",
        [operand],
        guard=guard,
        mfx="Ifx_Read",
        maddr=maddr,
        msize=8,
        bits=64,
        ins_addr=0x400030,
    )
    dst = VirtualVariable(4, 1, 64, VirtualVariableCategory.REGISTER, 16)
    block = Block(0x400030, 0, statements=[Assignment(5, dst, dirty)])

    new_block = ConstIncrementingRewriter(update_block=False).walk(block)
    new_stmt = new_block.statements[0]
    assert isinstance(new_stmt, Assignment)
    assert isinstance(new_stmt.src, DirtyExpression)
    assert len(new_stmt.src.operands) == 1
    assert new_stmt.src.operands[0].likes(operand)
    assert new_stmt.src.guard is not None and new_stmt.src.guard.likes(guard)
    assert new_stmt.src.idx == dirty.idx
    assert new_stmt.src.callee == dirty.callee
    assert new_stmt.src.mfx == dirty.mfx
    assert new_stmt.src.msize == dirty.msize
    assert new_stmt.src.bits == dirty.bits
    assert new_stmt.src.tags == dirty.tags
    new_maddr = new_stmt.src.maddr
    assert isinstance(new_maddr, Const)
    assert new_maddr.value == 2


def test_block_walkers_use_consistent_dirty_expression_child_slots():
    for operand_count in (0, 1, 3):
        operands = [Const(idx, 0x100 + idx, 64) for idx in range(operand_count)]
        guard = Const(10, 0x200, 1)
        maddr = Const(11, 0x300, 64)
        dirty = DirtyExpression(
            12,
            "helper",
            operands,
            guard=guard,
            mfx="Ifx_Read",
            maddr=maddr,
            msize=4,
            bits=32,
        )
        expected = [
            *((operand.value, idx) for idx, operand in enumerate(operands)),
            (guard.value, operand_count + 1),
            (maddr.value, operand_count + 2),
        ]

        for walker_cls in (ConstIndexRecordingWalker, ConstIndexRecordingViewer, ConstIndexRecordingRewriter):
            walker = walker_cls()
            walker.walk_expression(dirty)
            assert walker.const_indices == expected
