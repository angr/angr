from __future__ import annotations

from collections import OrderedDict
from types import SimpleNamespace

import networkx

from angr.ailment import AILBlockRewriter, AILBlockViewer, AILBlockWalker, Block
from angr.ailment.block_walker import _EXPR_WORKLIST_MIN_DEPTH, _ExprContinue, _ExprHandled
from angr.ailment.expression import (
    Array,
    BinaryOp,
    Call,
    ComboRegister,
    Const,
    Expression,
    FunctionLikeMacro,
    Load,
    MultiStatementExpression,
    Register,
    RustEnum,
    Struct,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, SideEffectStatement, Statement, Store
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.decompiler.counters.expression_counters import SingleExpressionCounter
from angr.analyses.decompiler.optimization_passes.cmpf_value_lowering import _has_cmpf_expr
from angr.analyses.decompiler.region_simplifiers.expr_folding import ExpressionReplacer as FoldingExpressionReplacer
from angr.analyses.decompiler.region_simplifiers.expr_folding import ExpressionSpotter
from angr.analyses.decompiler.variable_map import VariableMap
from angr.sim_variable import SimMemoryVariable
from angr.utils.ail import HasExprWalker
from angr.utils.ssa import AILBlacklistExprTypeWalker


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


def test_block_walker_handles_deep_binary_expressions():
    expr = Const(0, 0, 32)
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)

    walker = RecordingWalker()
    walker.walk_expression(expr)
    seen = walker.seen

    assert seen.count("BinaryOp") == 1500
    assert seen.count("Const") == 1501


def test_block_walker_handles_deep_binary_after_unrelated_handler_change():
    expr = Const(0, 0, 32)
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)

    walker = RecordingWalker()

    def handle_const(expr_idx, const, stmt_idx, stmt, block):
        del expr_idx, const, stmt_idx, stmt, block
        walker.seen.append("custom Const")

    walker.expr_handlers[Const] = handle_const
    walker.walk_expression(expr)

    assert walker.seen.count("BinaryOp") == 1500
    assert walker.seen.count("custom Const") == 1501


def test_block_walker_preserves_binary_postorder():
    class OrderedBinaryWalker(RecordingWalker):
        """Record constants and binary operators in visitation order."""

        def __init__(self):
            super().__init__()
            self.worklists = 0

        def _handle_binary_iteratively(self, *args, **kwargs):
            self.worklists += 1
            return super()._handle_binary_iteratively(*args, **kwargs)

        def _top(self, expr_idx, expr, stmt_idx, stmt, block):
            del expr_idx, stmt_idx, stmt, block
            if isinstance(expr, Const):
                self.seen.append(expr.value)
            else:
                assert isinstance(expr, BinaryOp)
                self.seen.append(expr.op)

    class RecursiveOrderedBinaryWalker(OrderedBinaryWalker):
        """Force the reference path through recursive BinaryOp handlers."""

        # pylint: disable=useless-parent-delegation

        def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
            return super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

    expr = BinaryOp(
        0,
        "Add",
        [
            BinaryOp(1, "Sub", [Const(2, 1, 32), Const(3, 2, 32)], False, bits=32),
            Const(4, 3, 32),
        ],
        False,
        bits=32,
    )
    expected = [1, 2, "Sub", 3, "Add"]
    next_idx = 5
    while expr.depth < _EXPR_WORKLIST_MIN_DEPTH:
        expr = BinaryOp(next_idx, "Add", [expr, Const(-next_idx, next_idx, 32)], False, bits=32)
        expected.extend([next_idx, "Add"])
        next_idx += 1
    assert expr.depth == _EXPR_WORKLIST_MIN_DEPTH

    walker = OrderedBinaryWalker()
    recursive_walker = RecursiveOrderedBinaryWalker()
    walker.walk_expression(expr)
    recursive_walker.walk_expression(expr)

    assert walker.worklists == 1
    assert recursive_walker.worklists == 0
    assert walker.seen == recursive_walker.seen == expected


def test_block_viewer_handles_deep_binary_expressions():
    class ConstCountingViewer(AILBlockViewer):
        """Count constants reached through viewer traversal."""

        def __init__(self):
            super().__init__()
            self.const_count = 0

        def _handle_Const(self, expr_idx, expr, stmt_idx, stmt, block):
            del expr_idx, expr, stmt_idx, stmt, block
            self.const_count += 1

    expr = Const(0, 0, 32)
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)

    viewer = ConstCountingViewer()
    viewer.walk_expression(expr)

    assert viewer.const_count == 1501


def test_cmpf_finder_handles_deep_binary_expressions():
    expr = Const(0, 0, 32)
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)

    assert _has_cmpf_expr(expr) is False

    cmpf = BinaryOp(1501, "CmpF", [Const(-1501, 0.0, 64), Const(-1502, 1.0, 64)], False, bits=32)
    expr = BinaryOp(1502, "Add", [expr, cmpf], False, bits=32)

    assert _has_cmpf_expr(expr) is True


def test_block_viewer_binary_does_not_call_top():
    class TopRecordingViewer(AILBlockViewer):
        """Record any expression result hook invoked by viewer traversal."""

        def __init__(self):
            super().__init__()
            self.top_calls = []

        def _top(
            self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
        ) -> None:
            del expr_idx, stmt_idx, stmt, block
            self.top_calls.append(expr)

    expr = BinaryOp(0, "Add", [Const(1, 1, 32), Const(2, 2, 32)], False, bits=32)
    viewer = TopRecordingViewer()

    assert viewer.walk_expression(expr) is None
    assert not viewer.top_calls


def test_clinic_collect_externs_handles_deep_binary_expressions():
    referenced_global = SimMemoryVariable(0x400000, 8, ident="extern_ref")
    stored_global = SimMemoryVariable(0x400008, 8, ident="extern_store")
    referenced_const = Const(0, 0x400000, 64)
    expr: Expression = referenced_const
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 64)], False, bits=64)

    dst = VirtualVariable(1501, 1, 64, VirtualVariableCategory.REGISTER, 16)
    store = Store(1503, Const(1504, 0x400008, 64), Const(1505, 1, 64), 8, "Iend_LE")
    block = Block(0x500000, 0, statements=[Assignment(1502, dst, expr), store])
    graph = networkx.DiGraph()
    graph.add_node(block)

    variable_map = VariableMap()
    variable_map.set_reference_variable(referenced_const, referenced_global)
    variable_map.set_variable(store, stored_global)
    global_manager = SimpleNamespace(get_variables=lambda: {referenced_global, stored_global})
    requested_flavors = []

    def get_global_manager(flavor):
        requested_flavors.append(flavor)
        assert flavor == "rust"
        return global_manager

    kb = SimpleNamespace(dec_variables=SimpleNamespace(get_global_manager=get_global_manager))

    # pylint: disable-next=protected-access
    assert Clinic._collect_externs(graph, kb, variable_map, "rust") == {referenced_global, stored_global}
    assert requested_flavors == ["rust"]


def test_expression_spotter_handles_deep_binary_mse_expressions():
    terminal = MultiStatementExpression(
        0,
        [
            SideEffectStatement(
                1,
                Call(2, "callee", args=[Load(3, Const(4, 0, 64), 8, "Iend_LE")], bits=64),
            )
        ],
        Const(5, 0, 64),
    )
    expr: Expression = terminal
    for idx in range(1, 1501):
        expr = BinaryOp(
            idx,
            "Add",
            [MultiStatementExpression(-idx, [], expr), Const(-idx - 1500, 0, 64)],
            False,
            bits=64,
        )

    spotter = ExpressionSpotter()
    spotter.walk_expression(expr)

    assert spotter.has_calls is True
    assert spotter.has_loads is True


def test_block_viewer_handles_deep_binary_after_handler_table_access():
    class ConstCountingViewer(AILBlockViewer):
        """Count constants reached through a materialized handler table."""

        def __init__(self):
            super().__init__()
            self.const_count = 0

        def _handle_Const(self, expr_idx, expr, stmt_idx, stmt, block):
            del expr_idx, expr, stmt_idx, stmt, block
            self.const_count += 1

    expr = Const(0, 0, 32)
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)

    viewer = ConstCountingViewer()
    assert viewer.expr_handlers[Const]
    viewer.walk_expression(expr)

    assert viewer.const_count == 1501


def test_block_rewriter_handles_deep_binary_expressions():
    expr = Const(0, 1, 32)
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)

    rewritten = ConstIncrementingRewriter().walk_expression(expr)

    for _ in range(1500):
        assert isinstance(rewritten, BinaryOp)
        assert isinstance(rewritten.operands[1], Const)
        assert rewritten.operands[1].value == 0
        rewritten = rewritten.operands[0]
    assert isinstance(rewritten, Const)
    assert rewritten.value == 2


def test_block_rewriter_preserves_expression_hook_order():
    class HookRecordingRewriter(AILBlockRewriter):
        """Record pre- and post-hooks around each expression."""

        def __init__(self):
            super().__init__()
            self.pre = []
            self.post = []

        def _pre_handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
            del stmt_idx, stmt, block
            self.pre.append((expr_idx, expr.idx))
            return expr

        def _post_handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
            del stmt_idx, stmt, block
            self.post.append((expr_idx, expr.idx))
            return expr

    expr = BinaryOp(10, "Add", [Const(11, 1, 32), Const(12, 2, 32)], False, bits=32)
    rewriter = HookRecordingRewriter()

    assert rewriter.walk_expression(expr) is expr
    assert rewriter.pre == [(0, 10), (0, 11), (1, 12)]
    assert rewriter.post == [(0, 11), (1, 12), (0, 10)]


def test_block_rewriter_post_binary_hook_handles_deep_expressions():
    class BinaryHookRewriter(AILBlockRewriter):
        """Record the postorder BinaryOp hook on the iterative path."""

        def __init__(self):
            super().__init__()
            self.seen = []

        def _post_handle_BinaryOp(self, expr, stmt_idx, stmt, block):
            del stmt_idx, stmt, block
            self.seen.append(expr.idx)
            return expr

    expr = Const(0, 0, 32)
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)

    rewriter = BinaryHookRewriter()
    assert rewriter.walk_expression(expr) is expr
    assert rewriter.seen == list(range(1, 1501))


def test_block_rewriter_redispatches_post_binary_hook_replacements():
    class BinaryHookRewriter(AILBlockRewriter):
        """Replace one BinaryOp and record the stabilizing redispatch."""

        def __init__(self):
            super().__init__()
            self.seen = []

        def _post_handle_BinaryOp(self, expr, stmt_idx, stmt, block):
            del stmt_idx, stmt, block
            self.seen.append(expr.op)
            if expr.op == "Add":
                return BinaryOp(expr.idx, "Sub", expr.operands, expr.signed, bits=expr.bits, **expr.tags)
            return expr

    rewriter = BinaryHookRewriter()
    rewritten = rewriter.walk_expression(BinaryOp(0, "Add", [Const(1, 1, 32), Const(2, 2, 32)], False, bits=32))

    assert isinstance(rewritten, BinaryOp)
    assert rewritten.op == "Sub"
    assert rewriter.seen == ["Add", "Sub"]


def test_block_rewriter_preserves_instance_handle_expr_override():
    nested = BinaryOp(1, "Sub", [Const(2, 1, 32), Const(3, 2, 32)], False, bits=32)
    expr = BinaryOp(0, "Add", [nested, Const(4, 3, 32)], False, bits=32)
    rewriter = AILBlockRewriter()
    seen = []
    default_handle_expr = type(rewriter)._handle_expr  # pylint: disable=protected-access

    def handle_expr(expr_idx, current_expr, stmt_idx, stmt, block):
        seen.append(current_expr.idx)
        return default_handle_expr(rewriter, expr_idx, current_expr, stmt_idx, stmt, block)

    rewriter.__dict__["_handle_expr"] = handle_expr
    rewriter.walk_expression(expr)

    assert seen == [0, 1, 2, 3, 4]


def test_block_rewriter_instance_entry_hook_handles_deep_binary_expressions():
    expr = Const(0, 0, 32)
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)

    rewriter = AILBlockRewriter()
    entered = 0
    default_enter_expr = rewriter._enter_expr  # pylint: disable=protected-access

    def enter_expr(expr_idx, current_expr, stmt_idx, stmt, block):
        nonlocal entered
        entered += 1
        return default_enter_expr(expr_idx, current_expr, stmt_idx, stmt, block)

    rewriter.__dict__["_enter_expr"] = enter_expr
    rewriter.walk_expression(expr)

    assert entered == 3001


def test_block_rewriter_handles_deep_binary_load_expressions():
    class LoadCountingRewriter(ConstIncrementingRewriter):
        """Count loads reached while rewriting constants."""

        def __init__(self):
            super().__init__()
            self.loads = 0

        def _pre_handle_Load(self, expr, stmt_idx, stmt, block):
            del expr, stmt_idx, stmt, block
            self.loads += 1

    expr = Const(0, 0, 64)
    for idx in range(1, 1501):
        expr = BinaryOp(
            idx,
            "Add",
            [Load(-idx, expr, 8, "Iend_LE"), Const(-idx - 1500, 0, 64)],
            False,
            bits=64,
        )
    expr = BinaryOp(1501, "Add", [expr, Const(-3001, 1, 64)], False, bits=64)

    rewriter = LoadCountingRewriter()
    rewritten = rewriter.walk_expression(expr)

    # The constant rewrite triggers the rewriter's stabilization pass, so every Load is observed twice.
    assert rewriter.loads == 3000
    assert isinstance(rewritten, BinaryOp)
    assert isinstance(rewritten.operands[1], Const)
    assert rewritten.operands[1].value == 2
    rewritten = rewritten.operands[0]
    for _ in range(1500):
        assert isinstance(rewritten, BinaryOp)
        rewritten = rewritten.operands[0]
        assert isinstance(rewritten, Load)
        rewritten = rewritten.addr
    assert isinstance(rewritten, Const)
    assert rewritten.value == 0


def test_block_rewriter_handles_deep_binary_after_handler_table_access():
    expr = Const(0, 1, 32)
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)

    rewriter = ConstIncrementingRewriter()
    assert rewriter.expr_handlers[Const]
    rewritten = rewriter.walk_expression(expr)

    for _ in range(1500):
        assert isinstance(rewritten, BinaryOp)
        rewritten = rewritten.operands[0]
    assert isinstance(rewritten, Const)
    assert rewritten.value == 2


def test_shallow_binary_expressions_skip_worklists():
    class WorklistRecordingWalker(RecordingWalker):
        """Record uses of the walker's iterative BinaryOp path."""

        def __init__(self):
            super().__init__()
            self.worklists = 0

        def _handle_binary_iteratively(self, *args, **kwargs):
            self.worklists += 1
            return super()._handle_binary_iteratively(*args, **kwargs)

    class WorklistRecordingRewriter(AILBlockRewriter):
        """Record uses of the rewriter's iterative BinaryOp path."""

        def __init__(self):
            super().__init__()
            self.worklists = 0

        def _handle_binary_mse_iteratively(self, *args, **kwargs):
            self.worklists += 1
            return super()._handle_binary_mse_iteratively(*args, **kwargs)

    expr = BinaryOp(0, "Add", [Const(1, 1, 32), Const(2, 2, 32)], False, bits=32)
    walker = WorklistRecordingWalker()
    rewriter = WorklistRecordingRewriter()

    walker.walk_expression(expr)
    rewritten = rewriter.walk_expression(expr)

    assert walker.worklists == 0
    assert rewriter.worklists == 0
    assert rewritten is expr


def test_binary_expression_worklist_depth_boundary():
    class WorklistRecordingWalker(RecordingWalker):
        """Record uses of the walker's iterative BinaryOp path."""

        def __init__(self):
            super().__init__()
            self.worklists = 0

        def _handle_binary_iteratively(self, *args, **kwargs):
            self.worklists += 1
            return super()._handle_binary_iteratively(*args, **kwargs)

    class WorklistRecordingRewriter(AILBlockRewriter):
        """Record uses of the rewriter's iterative BinaryOp path."""

        def __init__(self):
            super().__init__()
            self.worklists = 0

        def _handle_binary_mse_iteratively(self, *args, **kwargs):
            self.worklists += 1
            return super()._handle_binary_mse_iteratively(*args, **kwargs)

    def binary_chain(depth):
        """Build a left-associated BinaryOp chain with the requested depth."""

        expr = Const(0, 0, 32)
        for idx in range(1, depth + 1):
            expr = BinaryOp(idx, "Add", [expr, Const(-idx, idx, 32)], False, bits=32)
        return expr

    below = binary_chain(_EXPR_WORKLIST_MIN_DEPTH - 1)
    at = binary_chain(_EXPR_WORKLIST_MIN_DEPTH)
    assert below.depth == _EXPR_WORKLIST_MIN_DEPTH - 1
    assert at.depth == _EXPR_WORKLIST_MIN_DEPTH

    below_walker = WorklistRecordingWalker()
    below_rewriter = WorklistRecordingRewriter()
    below_walker.walk_expression(below)
    assert below_rewriter.walk_expression(below) is below
    assert below_walker.worklists == 0
    assert below_rewriter.worklists == 0

    at_walker = WorklistRecordingWalker()
    at_rewriter = WorklistRecordingRewriter()
    at_walker.walk_expression(at)
    assert at_rewriter.walk_expression(at) is at
    assert at_walker.worklists == 1
    assert at_rewriter.worklists == 1


def test_deep_binary_expressions_use_worklists():
    class WorklistRecordingWalker(RecordingWalker):
        """Record uses of the walker's iterative BinaryOp path."""

        def __init__(self):
            super().__init__()
            self.worklists = 0

        def _handle_binary_iteratively(self, *args, **kwargs):
            self.worklists += 1
            return super()._handle_binary_iteratively(*args, **kwargs)

    class WorklistRecordingRewriter(AILBlockRewriter):
        """Record uses of the rewriter's iterative BinaryOp path."""

        def __init__(self):
            super().__init__()
            self.worklists = 0

        def _handle_binary_mse_iteratively(self, *args, **kwargs):
            self.worklists += 1
            return super()._handle_binary_mse_iteratively(*args, **kwargs)

    expr = Const(0, 0, 32)
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)
    walker = WorklistRecordingWalker()
    rewriter = WorklistRecordingRewriter()

    walker.walk_expression(expr)
    rewritten = rewriter.walk_expression(expr)

    assert walker.worklists == 1
    assert rewriter.worklists == 1
    assert rewritten is expr


def test_single_expression_counter_handles_deep_binary_expressions():
    target = Const(0, 1, 32)
    expr = target
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)
    dst = VirtualVariable(1502, 1, 32, VirtualVariableCategory.REGISTER, 16)

    counter = SingleExpressionCounter(Assignment(1503, dst, expr), target)

    assert counter.count == 1


def test_has_expr_walker_handles_deep_binary_expressions():
    target = Const(0, 1, 32)
    expr = target
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)

    walker = HasExprWalker({target})
    walker.walk_expression(expr)

    assert walker.contains_exprs is True


def test_expression_protocol_can_prune_without_leaving():
    class PruningViewer(AILBlockViewer):
        """Record expression protocol entry and leave events while pruning one subtree."""

        def __init__(self):
            super().__init__()
            self.entered = []
            self.left = []

        def _enter_expr(self, expr_idx, expr, stmt_idx, stmt, block):
            self.entered.append(expr.idx)
            if expr.idx == 1:
                return _ExprHandled(None)
            return _ExprContinue(expr, expr.idx)

        def _leave_expr(self, expr_idx, original, prepared, result, state, stmt_idx, stmt, block):
            self.left.append(state)
            return result

    pruned = BinaryOp(1, "Add", [Const(2, 1, 32), Const(3, 2, 32)], False, bits=32)
    expr = BinaryOp(0, "Add", [pruned, Const(4, 3, 32)], False, bits=32)
    viewer = PruningViewer()

    viewer.walk_expression(expr)

    assert viewer.entered == [0, 1, 4]
    assert viewer.left == [4, 0]


def test_blacklist_walker_handles_deep_binary_inside_stateful_match():
    vvar = VirtualVariable(0, 7, 64, VirtualVariableCategory.REGISTER, 16)
    addr = vvar
    for idx in range(1, 1501):
        addr = BinaryOp(idx, "Add", [addr, Const(-idx, 0, 64)], False, bits=64)
    expr = Load(1501, addr, 8, "Iend_LE")

    ignored = AILBlacklistExprTypeWalker((Load,), skip_if_contains_vvar=7)
    ignored.walk_expression(expr)
    rejected = AILBlacklistExprTypeWalker((Load,), skip_if_contains_vvar=8)
    rejected.walk_expression(expr)

    assert ignored.has_blacklisted_exprs is False
    assert rejected.has_blacklisted_exprs is True


def test_block_rewriter_keeps_replacements_opaque():
    original = VirtualVariable(0, 1, 32, VirtualVariableCategory.REGISTER, 16)
    nested = VirtualVariable(1, 2, 32, VirtualVariableCategory.REGISTER, 24)
    replacement = BinaryOp(2, "Add", [nested, Const(3, 1, 32)], False, bits=32)
    nested_replacement = Const(4, 2, 32)
    rewriter = FoldingExpressionReplacer(
        {1: (replacement, None), 2: (nested_replacement, None)}, {1: None, 2: None}, None
    )

    rewritten = rewriter.walk_expression(original)

    assert rewritten is replacement
    assert isinstance(rewritten, BinaryOp)
    assert isinstance(rewritten.operands[0], VirtualVariable)
    assert rewritten.operands[0].varid == nested.varid


def test_deep_binary_ignores_unused_custom_container_handlers():
    class CustomContainerRewriter(AILBlockRewriter):
        """Fail if an unrelated custom container handler is dispatched."""

        def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
            raise AssertionError("unused Load handler was called")

        def _handle_MultiStatementExpression(self, expr_idx, expr, stmt_idx, stmt, block):
            raise AssertionError("unused MultiStatementExpression handler was called")

    expr = Const(0, 0, 32)
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx, 0, 32)], False, bits=32)

    assert CustomContainerRewriter().walk_expression(expr) is expr


def test_iterative_rewriter_dispatches_encountered_custom_mse_handler():
    class CustomMSERewriter(AILBlockRewriter):
        """Count and replace a custom MultiStatementExpression dispatch."""

        def __init__(self):
            super().__init__()
            self.seen = 0

        def _handle_MultiStatementExpression(self, expr_idx, expr, stmt_idx, stmt, block):
            self.seen += 1
            return Const(1, 42, 32)

    expr = MultiStatementExpression(0, [], Const(-1, 0, 32))
    for idx in range(1, 1501):
        expr = BinaryOp(idx, "Add", [expr, Const(-idx - 1, 0, 32)], False, bits=32)
    rewriter = CustomMSERewriter()

    rewritten = rewriter.walk_expression(expr)

    assert rewriter.seen == 1
    for _ in range(1500):
        assert isinstance(rewritten, BinaryOp)
        rewritten = rewritten.operands[0]
    assert isinstance(rewritten, Const)
    assert rewritten.value == 42


def test_iterative_rewriter_stabilizes_nested_frames_before_leaving():
    class StabilizingRewriter(AILBlockRewriter):
        """Exercise result stabilization before a nested frame is left."""

        def __init__(self):
            super().__init__()
            self.worklists = 0

        def _handle_binary_mse_iteratively(self, *args, **kwargs):
            self.worklists += 1
            return super()._handle_binary_mse_iteratively(*args, **kwargs)

        def _post_handle_MultiStatementExpression(self, expr, new_statements, new_expr):
            return Const(expr.idx, 1, expr.bits)

        def _handle_Const(self, expr_idx, expr, stmt_idx, stmt, block):
            if expr.value == 1:
                return Const(expr.idx, 2, expr.bits)
            return expr

        def _leave_expr(self, expr_idx, original, prepared, result, state, stmt_idx, stmt, block):
            if isinstance(original, MultiStatementExpression) and isinstance(result, Const) and result.value == 1:
                return Const(result.idx, 99, result.bits)
            return result

    class RecursiveStabilizingRewriter(StabilizingRewriter):
        """Force the reference path through recursive container handlers."""

        # pylint: disable=useless-parent-delegation

        def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
            return super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

        def _handle_MultiStatementExpression(self, expr_idx, expr, stmt_idx, stmt, block):
            return super()._handle_MultiStatementExpression(expr_idx, expr, stmt_idx, stmt, block)

    mse = MultiStatementExpression(1, [], Const(2, 0, 32))
    expr = BinaryOp(0, "Add", [mse, Const(3, 0, 32)], False, bits=32)
    wrappers = 0
    while expr.depth < _EXPR_WORKLIST_MIN_DEPTH:
        wrappers += 1
        expr = BinaryOp(-wrappers, "Add", [expr, Const(-1000 - wrappers, 0, 32)], False, bits=32)
    assert expr.depth == _EXPR_WORKLIST_MIN_DEPTH

    iterative_rewriter = StabilizingRewriter()
    recursive_rewriter = RecursiveStabilizingRewriter()
    iterative = iterative_rewriter.walk_expression(expr)
    recursive = recursive_rewriter.walk_expression(expr)

    assert iterative_rewriter.worklists == 1
    assert recursive_rewriter.worklists == 0
    assert iterative.likes(recursive)
    inner = iterative
    for _ in range(wrappers):
        assert isinstance(inner, BinaryOp)
        inner = inner.operands[0]
    assert isinstance(inner, BinaryOp)
    assert isinstance(inner.operands[0], Const)
    assert inner.operands[0].value == 2


def test_iterative_rewriter_reenters_children_during_stabilization():
    class ReentryRecordingRewriter(AILBlockRewriter):
        """Record re-entry and make the second visit affect the result."""

        def __init__(self):
            super().__init__()
            self.events = []
            self.worklists = 0

        def _handle_binary_mse_iteratively(self, *args, **kwargs):
            self.worklists += 1
            return super()._handle_binary_mse_iteratively(*args, **kwargs)

        @staticmethod
        def _describe(expr):
            return type(expr).__name__, expr.idx, expr.value if isinstance(expr, Const) else None

        def _enter_expr(self, expr_idx, expr, stmt_idx, stmt, block):
            self.events.append(("enter", *self._describe(expr)))
            if isinstance(expr, Const) and expr.value == 2:
                return _ExprHandled(Const(expr.idx, 3, expr.bits))
            return super()._enter_expr(expr_idx, expr, stmt_idx, stmt, block)

        def _leave_expr(self, expr_idx, original, prepared, result, state, stmt_idx, stmt, block):
            self.events.append(("leave", *self._describe(original), *self._describe(result)))
            return super()._leave_expr(expr_idx, original, prepared, result, state, stmt_idx, stmt, block)

        def _handle_Const(self, expr_idx, expr, stmt_idx, stmt, block):
            if expr.value == 1:
                return Const(expr.idx, 2, expr.bits)
            return expr

    class RecursiveReentryRecordingRewriter(ReentryRecordingRewriter):
        """Force the reference path through recursive BinaryOp and Load handlers."""

        # pylint: disable=useless-parent-delegation

        def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
            return super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

        def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
            return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    expr = BinaryOp(0, "Add", [Load(1, Const(2, 1, 32), 4, "Iend_LE"), Const(3, 0, 32)], False, bits=32)
    wrappers = 0
    while expr.depth < _EXPR_WORKLIST_MIN_DEPTH:
        wrappers += 1
        expr = BinaryOp(-wrappers, "Add", [expr, Const(-1000 - wrappers, 0, 32)], False, bits=32)
    assert expr.depth == _EXPR_WORKLIST_MIN_DEPTH
    iterative_rewriter = ReentryRecordingRewriter()
    recursive_rewriter = RecursiveReentryRecordingRewriter()

    iterative = iterative_rewriter.walk_expression(expr)
    recursive = recursive_rewriter.walk_expression(expr)

    assert iterative_rewriter.worklists == 1
    assert recursive_rewriter.worklists == 0
    assert iterative.likes(recursive)
    assert iterative_rewriter.events == recursive_rewriter.events
    inner = iterative
    for _ in range(wrappers):
        assert isinstance(inner, BinaryOp)
        inner = inner.operands[0]
    assert isinstance(inner, BinaryOp)
    assert isinstance(inner.operands[0], Load)
    assert isinstance(inner.operands[0].addr, Const)
    assert inner.operands[0].addr.value == 3


def test_rewriter_dispatches_custom_binary_handler():
    class CustomBinaryRewriter(AILBlockRewriter):
        """Record custom BinaryOp handler dispatches."""

        def __init__(self):
            super().__init__()
            self.seen = []

        def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
            self.seen.append(expr.idx)
            return super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

    nested = BinaryOp(1, "Sub", [Const(2, 2, 32), Const(3, 1, 32)], False, bits=32)
    expr = BinaryOp(0, "Add", [nested, Const(4, 3, 32)], False, bits=32)
    rewriter = CustomBinaryRewriter()

    assert rewriter.walk_expression(expr) is expr
    assert rewriter.seen == [0, 1]
