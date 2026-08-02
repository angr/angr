from __future__ import annotations

import networkx
import pytest

import angr
import angr.ailment.utils as ailment_utils
from angr import ailment
from angr.ailment.expression import DirtyExpression, Expression, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Statement
from angr.ailment.utils import (
    has_dirty_memory_read,
    has_dirty_memory_write,
    has_effectful_dirty_expression,
    is_effectful_dirty_expression,
)
from angr.analyses.decompiler.ail_simplifier import AILSimplifier
from angr.analyses.decompiler.block_simplifier import BlockSimplifier
from angr.analyses.decompiler.block_walkers import HasCallExprWalker, HasCallNotification
from angr.analyses.s_propagator import SPropagator
from angr.analyses.s_reaching_definitions import SRDAModel
from angr.code_location import AILCodeLocation


def _project():
    return angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)


def _dirty(
    idx: int,
    mfx: str | None,
    *,
    operands=(),
    guard=None,
    maddr=None,
    bits: int = 64,
) -> DirtyExpression:
    return DirtyExpression(
        idx,
        f"helper_{idx}",
        list(operands),
        guard=guard,
        mfx=mfx,
        maddr=maddr,
        msize=8 if maddr is not None else None,
        bits=bits,
    )


def _has_replacement(propagator: SPropagator, expressions) -> bool:
    return any(expr in replacements for replacements in propagator.replacements.values() for expr in expressions)


def _function_propagator(project, block: ailment.Block, manager: ailment.Manager) -> SPropagator:
    function = project.kb.functions.function(addr=block.addr, create=True)
    assert function is not None
    graph = networkx.DiGraph()
    graph.add_node(block)
    return SPropagator(project, subject=function, func_graph=graph, ail_manager=manager)


def _intervening_dirty_statement(idx: int, mfx: str | None, addr):
    return ailment.Stmt.DirtyStatement(
        idx,
        _dirty(idx + 1, mfx, maddr=addr if mfx is not None else None),
        ins_addr=0x1001,
    )


def _mse_use_with_dirty_write(idx: int, use, addr):
    write = ailment.Stmt.DirtyStatement(
        idx,
        _dirty(idx + 1, "Ifx_Write", maddr=addr),
        ins_addr=0x1001,
    )
    return ailment.Expr.MultiStatementExpression(idx + 2, [write], use)


def _legacy_dirty_effects(obj: Expression | Statement) -> int:
    effects = 0
    for memory_effects, bit in (
        (None, 1 << 0),
        (ailment_utils._DIRTY_MEMORY_READ_EFFECTS, 1 << 1),  # pylint:disable=protected-access
        (ailment_utils._DIRTY_MEMORY_WRITE_EFFECTS, 1 << 2),  # pylint:disable=protected-access
    ):
        finder = ailment_utils._EffectfulDirtyExpressionFinder(memory_effects)  # pylint:disable=protected-access
        try:
            if isinstance(obj, Expression):
                finder.walk_expression(obj)
            else:
                finder.walk_statement(obj)
        except ailment_utils._EffectfulDirtyExpressionFound:  # pylint:disable=protected-access
            effects |= bit
    return effects


def _dirty_expression_slot_roots():
    clean = ailment.Expr.Const(100, 0, 64)
    condition = ailment.Expr.Const(101, 1, 1)
    dirty = _dirty(102, "Ifx_Modify")
    dirty_condition = _dirty(103, "Ifx_Modify", bits=1)
    dirty_stmt = ailment.Stmt.DirtyStatement(104, dirty)
    return (
        ("unary-operand", ailment.Expr.UnaryOp(110, "Not", dirty, bits=64)),
        ("reinterpret-operand", ailment.Expr.Reinterpret(111, 64, "int", 64, "float", dirty)),
        ("convert-operand", ailment.Expr.Convert(112, 64, 64, False, dirty)),
        (
            "convert-rounding",
            ailment.Expr.Convert(113, 64, 64, False, clean, rounding_mode=dirty),
        ),
        ("binary-left", ailment.Expr.BinaryOp(114, "Add", (dirty, clean), bits=64)),
        ("binary-right", ailment.Expr.BinaryOp(115, "Add", (clean, dirty), bits=64)),
        (
            "binary-rounding",
            ailment.Expr.BinaryOp(116, "Add", (clean, clean), bits=64, rounding_mode=dirty),
        ),
        ("load-address", ailment.Expr.Load(117, dirty, 8, "Iend_LE")),
        ("load-guard", ailment.Expr.Load(118, clean, 8, "Iend_LE", guard=dirty_condition)),
        ("load-alt", ailment.Expr.Load(119, clean, 8, "Iend_LE", alt=dirty)),
        ("call-target", ailment.Expr.Call(120, dirty, args=[], bits=64)),
        ("call-argument", ailment.Expr.Call(121, "helper", args=[dirty], bits=64)),
        ("dirty-operand", _dirty(122, None, operands=(dirty,))),
        ("dirty-guard", _dirty(123, None, guard=dirty_condition)),
        ("dirty-address", _dirty(124, None, maddr=dirty)),
        ("vex-ccall-operand", ailment.Expr.VEXCCallExpression(125, "helper", [dirty], 64)),
        (
            "mse-statement",
            ailment.Expr.MultiStatementExpression(126, [dirty_stmt], clean),
        ),
        ("mse-expression", ailment.Expr.MultiStatementExpression(127, [], dirty)),
        ("struct-field", ailment.Expr.Struct(128, "S", {0: dirty}, {"value": 0}, 64)),
        ("enum-field", ailment.Expr.RustEnum(129, "Some", [dirty], 64)),
        ("array-element", ailment.Expr.Array(130, [dirty], 64)),
        (
            "let-definition",
            ailment.Expr.Let(131, [ailment.Stmt.Assignment(132, ailment.Expr.Tmp(133, 0, 64), dirty)], clean),
        ),
        ("let-source", ailment.Expr.Let(134, [], dirty)),
        ("macro-argument", ailment.Expr.FunctionLikeMacro(135, "format", [dirty], bits=64)),
        ("ite-condition", ailment.Expr.ITE(136, dirty_condition, clean, clean)),
        ("ite-false", ailment.Expr.ITE(137, condition, dirty, clean)),
        ("ite-true", ailment.Expr.ITE(138, condition, clean, dirty)),
        ("extract-base", ailment.Expr.Extract(139, 64, dirty, clean, "Iend_LE")),
        ("extract-offset", ailment.Expr.Extract(140, 64, clean, dirty, "Iend_LE")),
        ("insert-base", ailment.Expr.Insert(141, dirty, clean, clean, "Iend_LE")),
        ("insert-offset", ailment.Expr.Insert(142, clean, dirty, clean, "Iend_LE")),
        ("insert-value", ailment.Expr.Insert(143, clean, clean, dirty, "Iend_LE")),
    )


def _dirty_statement_slot_roots():
    clean = ailment.Expr.Const(200, 0, 64)
    condition = ailment.Expr.Const(201, 1, 1)
    dirty = _dirty(202, "Ifx_Modify")
    dirty_condition = _dirty(203, "Ifx_Modify", bits=1)
    return (
        ("assignment-destination", ailment.Stmt.Assignment(210, dirty, clean)),
        ("assignment-source", ailment.Stmt.Assignment(211, clean, dirty)),
        ("weak-destination", ailment.Stmt.WeakAssignment(212, dirty, clean)),
        ("weak-source", ailment.Stmt.WeakAssignment(213, clean, dirty)),
        ("store-address", ailment.Stmt.Store(214, dirty, clean, 8, "Iend_LE")),
        ("store-data", ailment.Stmt.Store(215, clean, dirty, 8, "Iend_LE")),
        ("store-guard", ailment.Stmt.Store(216, clean, clean, 8, "Iend_LE", guard=dirty_condition)),
        ("jump-target", ailment.Stmt.Jump(217, dirty)),
        ("cjump-condition", ailment.Stmt.ConditionalJump(218, dirty_condition, clean, clean)),
        ("cjump-true", ailment.Stmt.ConditionalJump(219, condition, dirty, clean)),
        ("cjump-false", ailment.Stmt.ConditionalJump(220, condition, clean, dirty)),
        ("side-effect-expression", ailment.Stmt.SideEffectStatement(221, dirty)),
        ("return-expression", ailment.Stmt.Return(222, [dirty])),
        ("cas-address", ailment.Stmt.CAS(223, dirty, clean, None, clean, None, clean, None, "Iend_LE")),
        ("cas-data-low", ailment.Stmt.CAS(224, clean, dirty, None, clean, None, clean, None, "Iend_LE")),
        ("cas-data-high", ailment.Stmt.CAS(225, clean, clean, dirty, clean, None, clean, None, "Iend_LE")),
        ("cas-expected-low", ailment.Stmt.CAS(226, clean, clean, None, dirty, None, clean, None, "Iend_LE")),
        ("cas-expected-high", ailment.Stmt.CAS(227, clean, clean, None, clean, dirty, clean, None, "Iend_LE")),
        ("cas-old-low", ailment.Stmt.CAS(228, clean, clean, None, clean, None, dirty, None, "Iend_LE")),
        ("cas-old-high", ailment.Stmt.CAS(229, clean, clean, None, clean, None, clean, dirty, "Iend_LE")),
        ("dirty-statement", ailment.Stmt.DirtyStatement(230, dirty)),
    )


@pytest.mark.parametrize("case", _dirty_expression_slot_roots(), ids=lambda case: case[0])
def test_native_dirty_effect_summary_matches_python_expression_walker(case):
    _, root = case

    assert root._dirty_effects() == 0b111  # pylint:disable=protected-access
    assert _legacy_dirty_effects(root) == 0b111
    assert has_effectful_dirty_expression(root)
    assert has_dirty_memory_read(root)
    assert has_dirty_memory_write(root)


@pytest.mark.parametrize("case", _dirty_statement_slot_roots(), ids=lambda case: case[0])
def test_native_dirty_effect_summary_matches_python_statement_walker(case):
    _, root = case

    assert root._dirty_effects() == 0b111  # pylint:disable=protected-access
    assert _legacy_dirty_effects(root) == 0b111
    assert has_effectful_dirty_expression(root)
    assert has_dirty_memory_read(root)
    assert has_dirty_memory_write(root)


@pytest.mark.parametrize(
    "mfx, expected_mask",
    (
        (None, 0b000),
        ("Ifx_None", 0b001),
        ("Ifx_Read", 0b011),
        ("Ifx_Write", 0b101),
        ("Ifx_Modify", 0b111),
        ("Ifx_Unknown", 0b001),
    ),
)
def test_native_dirty_effect_mask_protocol(mfx, expected_mask):
    root = _dirty(240, mfx)

    assert root._dirty_effects() == expected_mask  # pylint:disable=protected-access
    assert _legacy_dirty_effects(root) == expected_mask


def test_native_dirty_effect_summary_ors_duplicate_bits():
    left = _dirty(241, "Ifx_None")
    right = _dirty(242, "Ifx_None")
    root = ailment.Expr.Call(243, left, args=[right], bits=64)

    assert root._dirty_effects() == 0b001  # pylint:disable=protected-access
    assert _legacy_dirty_effects(root) == 0b001


def test_native_dirty_effect_summary_ignores_unevaluated_metadata_slots():
    clean = ailment.Expr.Const(244, 0, 64)
    dirty = _dirty(245, "Ifx_Modify")
    roots = (
        ailment.Expr.Call(246, "helper", args=[clean], bits=64, arg_vvars=[dirty]),
        ailment.Stmt.SideEffectStatement(247, clean, ret_expr=dirty, fp_ret_expr=dirty),
    )

    for root in roots:
        assert root._dirty_effects() == 0  # pylint:disable=protected-access
        assert _legacy_dirty_effects(root) == 0


def test_native_dirty_effect_summary_treats_non_dirty_statement_payload_as_opaque():
    root = ailment.Stmt.DirtyStatement(248, ailment.Expr.Const(249, 0, 64))

    assert root._dirty_effects() == 0b111  # pylint:disable=protected-access
    assert _legacy_dirty_effects(root) == 0b111


def test_native_dirty_effect_summary_observes_mutations_without_stale_cache():
    root = ailment.Expr.Load(250, ailment.Expr.Const(251, 0x3000, 64), 8, "Iend_LE")
    assert root._dirty_effects() == 0  # pylint:disable=protected-access

    root.guard = _dirty(252, "Ifx_Write", bits=1)
    assert root._dirty_effects() == 0b101  # pylint:disable=protected-access

    root.guard = None
    assert root._dirty_effects() == 0  # pylint:disable=protected-access


def test_native_dirty_effect_summary_survives_copy_and_serialization():
    expr = ailment.Expr.MultiStatementExpression(
        253,
        [ailment.Stmt.DirtyStatement(254, _dirty(255, None))],
        ailment.Expr.Const(256, 0, 64),
    )
    stmt = ailment.Stmt.Assignment(257, ailment.Expr.Tmp(258, 0, 64), _dirty(259, "Ifx_Read"))

    for clone in (expr.copy(), Expression.from_bytes(expr.to_bytes())):
        assert clone._dirty_effects() == 0b111  # pylint:disable=protected-access
    for clone in (stmt.copy(), Statement.from_bytes(stmt.to_bytes())):
        assert clone._dirty_effects() == 0b011  # pylint:disable=protected-access


def test_native_dirty_effect_summary_handles_deep_expression_chain():
    root = _dirty(260, "Ifx_Write")
    for idx in range(261, 773):
        root = ailment.Expr.UnaryOp(idx, "Not", root, bits=64)

    assert root._dirty_effects() == 0b101  # pylint:disable=protected-access


def test_dirty_effect_classification_preserves_vex_semantics():
    pure = _dirty(0, None)
    guest_state_effect = _dirty(1, "Ifx_None")
    read = _dirty(2, "Ifx_Read")
    write = _dirty(3, "Ifx_Write")
    modify = _dirty(4, "Ifx_Modify")

    assert not is_effectful_dirty_expression(pure)
    assert not has_effectful_dirty_expression(pure)
    assert not has_dirty_memory_read(pure)
    assert not has_dirty_memory_write(pure)
    assert is_effectful_dirty_expression(guest_state_effect)
    assert has_effectful_dirty_expression(guest_state_effect)
    assert not has_dirty_memory_read(guest_state_effect)
    assert not has_dirty_memory_write(guest_state_effect)

    assert has_dirty_memory_read(read)
    assert not has_dirty_memory_write(read)
    assert not has_dirty_memory_read(write)
    assert has_dirty_memory_write(write)
    assert has_dirty_memory_read(modify)
    assert has_dirty_memory_write(modify)

    opaque_stmt = ailment.Stmt.DirtyStatement(5, pure)
    nested_stmt = ailment.Expr.MultiStatementExpression(6, [opaque_stmt], ailment.Expr.Const(7, 0, 64))
    assert has_effectful_dirty_expression(nested_stmt)
    assert has_dirty_memory_read(nested_stmt)
    assert has_dirty_memory_write(nested_stmt)


@pytest.mark.parametrize(
    "mfx, expected_read, expected_write",
    (
        (None, True, True),
        ("Ifx_None", False, False),
        ("Ifx_Read", True, False),
        ("Ifx_Write", False, True),
        ("Ifx_Modify", True, True),
    ),
)
def test_dirty_statement_memory_effect_truth_table(mfx, expected_read, expected_write):
    stmt = ailment.Stmt.DirtyStatement(8, _dirty(9, mfx))

    assert has_effectful_dirty_expression(stmt)
    assert has_dirty_memory_read(stmt) is expected_read
    assert has_dirty_memory_write(stmt) is expected_write


def test_dirty_effect_search_recurses_through_nonmatching_dirty_fields():
    nested_write = _dirty(10, "Ifx_Write")
    roots = (
        _dirty(11, "Ifx_Read", operands=(nested_write,)),
        _dirty(12, None, guard=nested_write),
        _dirty(13, "Ifx_None", maddr=nested_write),
    )

    for root in roots:
        assert has_effectful_dirty_expression(root)
        assert has_dirty_memory_write(root)

    assert not is_effectful_dirty_expression(roots[1])


def test_clean_rust_expressions_skip_python_dirty_effect_walker(monkeypatch):
    vvar = ailment.Expr.VirtualVariable(14, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    expressions = (
        ailment.Expr.Const(15, 1, 64),
        ailment.Expr.Tmp(16, 0, 64),
        ailment.Expr.Register(17, 16, 64),
        ailment.Expr.ComboRegister(
            18,
            [ailment.Expr.Register(19, 16, 32), ailment.Expr.Register(20, 20, 32)],
        ),
        ailment.Expr.Phi(21, 64, [((0x1000, 0), vvar)]),
        vvar,
        ailment.Expr.StringLiteral(22, "clean", 40),
        ailment.Expr.VEXCCallExpression(23, "clean_helper", [ailment.Expr.Const(24, 0, 64)], 64),
    )
    assert all(expr.depth == 0 for expr in expressions)

    def unexpected_finder(_memory_effects):
        raise AssertionError("Rust expression constructed a Python dirty-effect walker")

    monkeypatch.setattr(ailment_utils, "_EffectfulDirtyExpressionFinder", unexpected_finder)
    for query in (has_effectful_dirty_expression, has_dirty_memory_read, has_dirty_memory_write):
        assert all(not query(expr) for expr in expressions)


def test_clean_rust_statements_skip_python_dirty_effect_walker(monkeypatch):
    addr = ailment.Expr.Const(25, 0x3000, 64)
    value = ailment.Expr.Const(26, 0, 32)
    register = ailment.Expr.Register(27, 16, 32)
    statements = (
        ailment.Stmt.Assignment(28, register, value),
        ailment.Stmt.WeakAssignment(29, register, value),
        ailment.Stmt.Label(30, "clean"),
        ailment.Stmt.Store(31, addr, value, 4, "Iend_LE", guard=ailment.Expr.Const(32, 1, 1)),
        ailment.Stmt.Jump(33, addr),
        ailment.Stmt.ConditionalJump(34, ailment.Expr.Const(35, 1, 1), addr, addr),
        ailment.Stmt.SideEffectStatement(36, value, ret_expr=register, fp_ret_expr=register),
        ailment.Stmt.Return(37, [value]),
        ailment.Stmt.CAS(38, addr, value, value, value, value, register, register, "Iend_LE"),
        ailment.Stmt.NoOp(39),
    )
    assert all(stmt.depth == 1 for stmt in statements if not isinstance(stmt, (ailment.Stmt.Label, ailment.Stmt.NoOp)))

    def unexpected_finder(_memory_effects):
        raise AssertionError("Rust statement constructed a Python dirty-effect walker")

    monkeypatch.setattr(ailment_utils, "_EffectfulDirtyExpressionFinder", unexpected_finder)
    for query in (has_effectful_dirty_expression, has_dirty_memory_read, has_dirty_memory_write):
        assert all(not query(stmt) for stmt in statements)


def _dirty_hidden_statement_roots():
    addr = ailment.Expr.Const(50, 0x3000, 64)
    value = ailment.Expr.Const(51, 0, 32)
    register = ailment.Expr.Register(52, 16, 32)
    condition = ailment.Expr.Const(53, 1, 1)
    return (
        ailment.Stmt.Store(54, addr, value, 4, "Iend_LE", guard=_dirty(55, "Ifx_Write", bits=1)),
        ailment.Stmt.ConditionalJump(56, condition, _dirty(57, "Ifx_Write"), addr),
        ailment.Stmt.ConditionalJump(58, condition, addr, _dirty(59, "Ifx_Write")),
        ailment.Stmt.CAS(64, addr, value, _dirty(65, "Ifx_Write", bits=32), value, None, register, None, "Iend_LE"),
        ailment.Stmt.CAS(66, addr, value, None, value, _dirty(67, "Ifx_Write", bits=32), register, None, "Iend_LE"),
        ailment.Stmt.CAS(68, addr, value, None, value, None, register, _dirty(69, "Ifx_Write", bits=32), "Iend_LE"),
    )


@pytest.mark.parametrize(
    "stmt",
    _dirty_hidden_statement_roots(),
    ids=("store-guard", "cjump-true", "cjump-false", "cas-data", "cas-expected", "cas-old"),
)
def test_native_statement_summary_checks_hidden_evaluated_slots(stmt):
    assert stmt.depth == 1
    assert has_effectful_dirty_expression(stmt)
    assert has_dirty_memory_write(stmt)


def test_dirty_effect_queries_accept_python_statement_subclasses():
    from angr.analyses.decompiler.structurer_nodes import IncompleteSwitchCaseHeadStatement

    stmt = IncompleteSwitchCaseHeadStatement(70, ailment.Expr.Const(71, 0, 32), [])
    assert isinstance(stmt, Statement)
    assert not has_effectful_dirty_expression(stmt)
    assert not has_dirty_memory_read(stmt)
    assert not has_dirty_memory_write(stmt)


def _dirty_evaluated_slot_roots():
    addr = ailment.Expr.Const(30, 0x3000, 64)
    guard = ailment.Expr.Const(31, 1, 1)
    value = ailment.Expr.Const(32, 0, 32)
    return (
        ailment.Expr.Load(
            33,
            addr,
            4,
            "Iend_LE",
            guard=_dirty(34, "Ifx_Write", maddr=addr, bits=1),
            alt=value,
        ),
        ailment.Expr.Load(
            35,
            addr,
            4,
            "Iend_LE",
            guard=guard,
            alt=_dirty(36, "Ifx_Write", maddr=addr, bits=32),
        ),
        ailment.Expr.BinaryOp(
            37,
            "Add",
            (value, value),
            bits=32,
            floating_point=True,
            rounding_mode=_dirty(38, "Ifx_Write", maddr=addr, bits=32),
        ),
        ailment.Expr.Convert(
            39,
            32,
            64,
            False,
            value,
            rounding_mode=_dirty(40, "Ifx_Write", maddr=addr, bits=32),
        ),
        ailment.Expr.Let(
            41,
            [
                ailment.Stmt.Assignment(
                    42,
                    ailment.Expr.Tmp(43, 0, 32),
                    _dirty(44, "Ifx_Write", maddr=addr, bits=32),
                )
            ],
            value,
        ),
        ailment.Expr.Let(45, [], _dirty(46, "Ifx_Write", maddr=addr, bits=32)),
    )


@pytest.mark.parametrize(
    "root",
    _dirty_evaluated_slot_roots(),
    ids=("load-guard", "load-alt", "binary-rounding", "convert-rounding", "let-def", "let-src"),
)
def test_dirty_effect_search_covers_all_evaluated_child_slots(root):
    assert root.depth > 0
    assert has_effectful_dirty_expression(root)
    assert has_dirty_memory_write(root)

    with pytest.raises(HasCallNotification):
        HasCallExprWalker().walk_expression(root)


def test_has_call_walker_covers_evaluated_load_alt():
    root = ailment.Expr.Load(
        47,
        ailment.Expr.Const(48, 0x3000, 64),
        4,
        "Iend_LE",
        guard=ailment.Expr.Const(49, 1, 1),
        alt=ailment.Expr.Call(50, "fallback", args=[], bits=32),
    )

    with pytest.raises(HasCallNotification):
        HasCallExprWalker().walk_expression(root)


def test_has_call_walker_treats_ifx_none_and_nested_dirty_as_effects():
    walker = HasCallExprWalker()
    walker.walk_expression(_dirty(20, None))

    with pytest.raises(HasCallNotification):
        walker.walk_statement(ailment.Stmt.DirtyStatement(21, _dirty(22, None)))

    with pytest.raises(HasCallNotification):
        walker.walk_expression(_dirty(23, "Ifx_None"))

    with pytest.raises(HasCallNotification):
        walker.walk_expression(_dirty(24, None, operands=(_dirty(25, "Ifx_Write"),)))


def test_lifted_cpuid_and_memory_fence_preserve_converter_effect_metadata():
    project = angr.load_shellcode(b"\x0f\xa2\xc3", "AMD64", load_address=0x1000)
    manager = ailment.Manager(arch=project.arch)
    vex_block = project.factory.block(0x1000, size=2, opt_level=0).vex
    block = ailment.IRSBConverter.convert(vex_block, manager)
    dirty_statements = [stmt for stmt in block.statements if isinstance(stmt, ailment.Stmt.DirtyStatement)]
    dirty_pairs: list[tuple[Statement, DirtyExpression]] = []
    for stmt in dirty_statements:
        dirty = stmt.dirty
        assert isinstance(dirty, DirtyExpression)
        dirty_pairs.append((stmt, dirty))

    cpuid_stmt, cpuid = next(pair for pair in dirty_pairs if pair[1].callee.startswith("amd64g_dirtyhelper_CPUID"))
    fence_stmt, fence = next(pair for pair in dirty_pairs if pair[1].callee.startswith("MBusEvent-"))
    assert cpuid.mfx == "Ifx_None"
    assert has_effectful_dirty_expression(cpuid_stmt)
    assert not has_dirty_memory_read(cpuid_stmt)
    assert not has_dirty_memory_write(cpuid_stmt)
    assert fence.callee.startswith("MBusEvent-")
    assert fence.mfx is None
    assert has_effectful_dirty_expression(fence_stmt)
    assert has_dirty_memory_read(fence_stmt)
    assert has_dirty_memory_write(fence_stmt)

    simplified = BlockSimplifier(project, block, manager, peephole_optimizations=[]).result_block
    assert simplified is not None
    simplified_effects = set()
    for stmt in simplified.statements:
        if isinstance(stmt, ailment.Stmt.DirtyStatement):
            dirty = stmt.dirty
            assert isinstance(dirty, DirtyExpression)
            simplified_effects.add((dirty.callee, dirty.mfx))
    assert (cpuid.callee, "Ifx_None") in simplified_effects
    assert (fence.callee, None) in simplified_effects


@pytest.mark.parametrize("dst_kind", ("tmp", "register"))
def test_block_simplifier_preserves_unused_ifx_none_dirty_assignment(dst_kind):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    dst = ailment.Expr.Tmp(0, 0, 64) if dst_kind == "tmp" else ailment.Expr.Register(0, 16, 64)
    effect = _dirty(1, "Ifx_None")
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(2, dst, effect, ins_addr=0x1000),
            ailment.Stmt.Return(3, [], ins_addr=0x1001),
        ],
        idx=0,
    )

    simplified = BlockSimplifier(project, block, manager, peephole_optimizations=[]).result_block

    assert simplified is not None
    assert any(
        isinstance(stmt, ailment.Stmt.Assignment)
        and isinstance(stmt.src, DirtyExpression)
        and stmt.src.callee == effect.callee
        for stmt in simplified.statements
    )


def test_block_simplifier_preserves_unused_mse_with_opaque_dirty_statement():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    opaque_stmt = ailment.Stmt.DirtyStatement(0, _dirty(1, None), ins_addr=0x1000)
    mse = ailment.Expr.MultiStatementExpression(2, [opaque_stmt], ailment.Expr.Const(3, 0, 64))
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(4, ailment.Expr.Tmp(5, 0, 64), mse, ins_addr=0x1000),
            ailment.Stmt.Return(6, [], ins_addr=0x1001),
        ],
        idx=0,
    )

    simplified = BlockSimplifier(project, block, manager, peephole_optimizations=[]).result_block

    assert simplified is not None
    assert any(
        isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.MultiStatementExpression)
        for stmt in simplified.statements
    )


def test_block_simplifier_removes_unused_pure_dirty_expression():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    pure = _dirty(0, None)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(1, ailment.Expr.Tmp(2, 0, 64), pure, ins_addr=0x1000),
            ailment.Stmt.Return(3, [], ins_addr=0x1001),
        ],
        idx=0,
    )

    simplified = BlockSimplifier(project, block, manager, peephole_optimizations=[]).result_block

    assert simplified is not None
    assert not any(
        isinstance(stmt, ailment.Stmt.Assignment)
        and isinstance(stmt.src, DirtyExpression)
        and stmt.src.callee == pure.callee
        for stmt in simplified.statements
    )


def test_block_simplifier_propagates_pure_dirty_expression():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    tmp_def = ailment.Expr.Tmp(0, 0, 64)
    tmp_use = ailment.Expr.Tmp(1, 0, 64)
    pure = _dirty(2, None)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(3, tmp_def, pure, ins_addr=0x1000),
            ailment.Stmt.Assignment(4, ailment.Expr.Register(5, 16, 64), tmp_use, ins_addr=0x1001),
            ailment.Stmt.Return(6, [], ins_addr=0x1002),
        ],
        idx=0,
    )

    simplified = BlockSimplifier(project, block, manager, peephole_optimizations=[]).result_block

    assert simplified is not None
    assert not any(
        isinstance(stmt, ailment.Stmt.Assignment)
        and isinstance(stmt.dst, ailment.Expr.Tmp)
        and stmt.dst.tmp_idx == tmp_def.tmp_idx
        for stmt in simplified.statements
    )
    assert any(
        isinstance(stmt, ailment.Stmt.Assignment)
        and isinstance(stmt.dst, ailment.Expr.Register)
        and isinstance(stmt.src, DirtyExpression)
        and stmt.src.callee == pure.callee
        for stmt in simplified.statements
    )


@pytest.mark.parametrize("source_kind", ("pure", "nested_dirty", "converted_dirty", "dirty_statement_mse"))
def test_effectful_dirty_definition_protects_entire_cyclic_vvar_component(source_kind):
    project = _project()
    vvar_1_def = VirtualVariable(0, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_1_use = VirtualVariable(1, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_2_def = VirtualVariable(2, 2, 64, VirtualVariableCategory.REGISTER, oident=24)
    vvar_2_use = VirtualVariable(3, 2, 64, VirtualVariableCategory.REGISTER, oident=24)

    if source_kind == "pure":
        source = _dirty(4, None, operands=(vvar_2_use,))
    elif source_kind == "nested_dirty":
        source = _dirty(5, None, operands=(vvar_2_use, _dirty(6, "Ifx_None")))
    elif source_kind == "converted_dirty":
        inner = ailment.Expr.BinaryOp(7, "Add", [vvar_2_use, _dirty(8, "Ifx_None")], bits=64)
        source = ailment.Expr.Convert(9, 64, 64, False, inner)
    else:
        opaque_stmt = ailment.Stmt.DirtyStatement(10, _dirty(11, None))
        source = ailment.Expr.MultiStatementExpression(12, [opaque_stmt], vvar_2_use)
    phi = ailment.Expr.Phi(6, 64, [((0x1000, 0), vvar_1_use)])
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(13, vvar_1_def, source),
            ailment.Stmt.Assignment(14, vvar_2_def, phi),
        ],
        idx=0,
    )
    graph = networkx.DiGraph()
    graph.add_node(block)

    rd = SRDAModel(graph, None, project.arch)
    rd.varid_to_vvar = {1: vvar_1_def, 2: vvar_2_def}
    rd.phi_vvar_ids = {2}
    rd.phivarid_to_varids = {2: {1}}
    rd.all_vvar_uses[1].append((vvar_1_use, AILCodeLocation(block.addr, block.idx, 1)))
    rd.all_vvar_uses[2].append((vvar_2_use, AILCodeLocation(block.addr, block.idx, 0)))

    simplifier = object.__new__(AILSimplifier)
    simplifier.func_graph = graph
    removable = simplifier._find_cyclic_dependent_phis_and_dirty_vvars(rd, set())

    assert removable == ({1, 2} if source_kind == "pure" else set())


def test_spropagator_guards_forced_stack_and_independent_vvar_paths():
    project = _project()
    manager = ailment.Manager(arch=project.arch)

    stack_def = VirtualVariable(0, 1, 64, VirtualVariableCategory.STACK, oident=-8)
    stack_use = VirtualVariable(1, 1, 64, VirtualVariableCategory.STACK, oident=-8)
    stack_block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(2, stack_def, _dirty(3, "Ifx_None"), ins_addr=0x1000),
            ailment.Stmt.Return(4, [stack_use], ins_addr=0x1001),
        ],
        idx=0,
    )
    stack_prop = SPropagator(
        project,
        subject=stack_block,
        ail_manager=manager,
        stack_arg_offsets={-8},
    )
    assert not _has_replacement(stack_prop, (stack_use,))

    vvar_def = VirtualVariable(5, 2, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_0 = VirtualVariable(6, 2, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_1 = VirtualVariable(7, 2, 64, VirtualVariableCategory.REGISTER, oident=16)
    nested_effect = _dirty(8, None, operands=(_dirty(9, "Ifx_Write"),))
    vvar_block = ailment.Block(
        0x2000,
        1,
        statements=[
            ailment.Stmt.Assignment(10, vvar_def, nested_effect, ins_addr=0x2000),
            ailment.Stmt.ConditionalJump(
                11,
                vvar_use_0,
                ailment.Expr.Const(12, 0x2000, 64),
                ailment.Expr.Const(13, 0x3000, 64),
                true_target_idx=0,
                ins_addr=0x2001,
            ),
            ailment.Stmt.Jump(14, vvar_use_1, ins_addr=0x2002),
        ],
        idx=0,
    )
    vvar_prop = _function_propagator(project, vvar_block, manager)
    assert not _has_replacement(vvar_prop, (vvar_use_0, vvar_use_1))
    assert vvar_def.varid not in vvar_prop.dead_vvar_ids


@pytest.mark.parametrize(
    "mfx, expected_replacement",
    (("Ifx_Read", True), ("Ifx_Write", False), (None, False)),
)
def test_spropagator_switch_path_does_not_bypass_load_memory_safety(mfx, expected_replacement):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    vvar_def = VirtualVariable(1, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_0 = VirtualVariable(2, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    vvar_use_1 = VirtualVariable(3, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
    block = ailment.Block(
        0x2000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                4,
                vvar_def,
                ailment.Expr.Load(5, addr, 8, "Iend_LE"),
                ins_addr=0x2000,
            ),
            _intervening_dirty_statement(6, mfx, addr),
            ailment.Stmt.ConditionalJump(
                8,
                vvar_use_0,
                ailment.Expr.Const(9, 0x2000, 64),
                ailment.Expr.Const(10, 0x3000, 64),
                true_target_idx=0,
                ins_addr=0x2001,
            ),
            ailment.Stmt.Jump(11, vvar_use_1, ins_addr=0x2002),
        ],
        idx=0,
    )

    propagator = _function_propagator(project, block, manager)
    assert _has_replacement(propagator, (vvar_use_0, vvar_use_1)) is expected_replacement
    if not expected_replacement:
        assert vvar_def.varid not in propagator.dead_vvar_ids


@pytest.mark.parametrize("source_kind", ("ifx_none", "dirty_statement"))
def test_spropagator_does_not_propagate_effectful_dirty_tmp(source_kind):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    tmp_def = ailment.Expr.Tmp(0, 0, 64)
    tmp_use = ailment.Expr.Tmp(1, 0, 64)
    if source_kind == "ifx_none":
        source = _dirty(3, "Ifx_None")
    else:
        opaque_stmt = ailment.Stmt.DirtyStatement(3, _dirty(4, None))
        source = ailment.Expr.MultiStatementExpression(5, [opaque_stmt], ailment.Expr.Const(6, 0, 64))
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(7, tmp_def, source, ins_addr=0x1000),
            ailment.Stmt.Assignment(8, ailment.Expr.Register(9, 16, 64), tmp_use, ins_addr=0x1001),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert not _has_replacement(propagator, (tmp_use,))


@pytest.mark.parametrize(
    "mfx, expected_replacement",
    (("Ifx_Read", True), ("Ifx_Write", False), (None, False)),
)
def test_spropagator_tmp_load_crosses_reads_but_not_dirty_writes(mfx, expected_replacement):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    tmp_def = ailment.Expr.Tmp(1, 0, 32)
    tmp_use = ailment.Expr.Tmp(2, 0, 32)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                3,
                tmp_def,
                ailment.Expr.Load(4, addr, 4, "Iend_LE"),
                ins_addr=0x1000,
            ),
            _intervening_dirty_statement(5, mfx, addr),
            ailment.Stmt.Assignment(8, ailment.Expr.Register(9, 16, 32), tmp_use, ins_addr=0x1002),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert _has_replacement(propagator, (tmp_use,)) is expected_replacement


@pytest.mark.parametrize("mfx", ("Ifx_Write", "Ifx_Modify", None))
def test_spropagator_same_instruction_dirty_write_still_blocks_tmp_load(mfx):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    tmp_def = ailment.Expr.Tmp(1, 0, 32)
    tmp_use = ailment.Expr.Tmp(2, 0, 32)
    dirty_stmt = ailment.Stmt.DirtyStatement(
        3,
        _dirty(4, mfx, maddr=addr if mfx is not None else None),
        ins_addr=0x1000,
    )
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                5,
                tmp_def,
                ailment.Expr.Load(6, addr, 4, "Iend_LE"),
                ins_addr=0x1000,
            ),
            dirty_stmt,
            ailment.Stmt.Assignment(7, ailment.Expr.Register(8, 16, 32), tmp_use, ins_addr=0x1000),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert not _has_replacement(propagator, (tmp_use,))


def test_spropagator_keeps_same_instruction_store_exemption_for_tmp_load():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    tmp_def = ailment.Expr.Tmp(1, 0, 32)
    tmp_use = ailment.Expr.Tmp(2, 0, 32)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                3,
                tmp_def,
                ailment.Expr.Load(4, addr, 4, "Iend_LE"),
                ins_addr=0x1000,
            ),
            ailment.Stmt.Store(
                5,
                addr,
                ailment.Expr.Const(6, 1, 32),
                4,
                "Iend_LE",
                ins_addr=0x1000,
            ),
            ailment.Stmt.Assignment(7, ailment.Expr.Register(8, 16, 32), tmp_use, ins_addr=0x1000),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert _has_replacement(propagator, (tmp_use,))


def test_spropagator_propagates_untagged_tmp_load_without_memory_write():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    tmp_def = ailment.Expr.Tmp(1, 0, 32)
    tmp_use = ailment.Expr.Tmp(2, 0, 32)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(3, tmp_def, ailment.Expr.Load(4, addr, 4, "Iend_LE")),
            ailment.Stmt.Assignment(5, ailment.Expr.Register(6, 16, 32), tmp_use),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert _has_replacement(propagator, (tmp_use,))


@pytest.mark.parametrize(
    "endpoint_ins_addr, store_ins_addr",
    ((None, None), (0x1000, None), (0x1000, 0x1001)),
)
def test_spropagator_does_not_exempt_untagged_or_different_instruction_store(endpoint_ins_addr, store_ins_addr):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    tmp_def = ailment.Expr.Tmp(1, 0, 32)
    tmp_use = ailment.Expr.Tmp(2, 0, 32)
    endpoint_tags = {} if endpoint_ins_addr is None else {"ins_addr": endpoint_ins_addr}
    store_tags = {} if store_ins_addr is None else {"ins_addr": store_ins_addr}
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                3,
                tmp_def,
                ailment.Expr.Load(4, addr, 4, "Iend_LE"),
                **endpoint_tags,
            ),
            ailment.Stmt.Store(
                5,
                addr,
                ailment.Expr.Const(6, 1, 32),
                4,
                "Iend_LE",
                **store_tags,
            ),
            ailment.Stmt.Assignment(7, ailment.Expr.Register(8, 16, 32), tmp_use, **endpoint_tags),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert not _has_replacement(propagator, (tmp_use,))


def test_spropagator_does_not_move_tmp_load_past_dirty_write_in_use_mse():
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    tmp_def = ailment.Expr.Tmp(1, 0, 32)
    tmp_use = ailment.Expr.Tmp(2, 0, 32)
    use_mse = _mse_use_with_dirty_write(3, tmp_use, addr)
    block = ailment.Block(
        0x1000,
        1,
        statements=[
            ailment.Stmt.Assignment(
                6,
                tmp_def,
                ailment.Expr.Load(7, addr, 4, "Iend_LE"),
                ins_addr=0x1000,
            ),
            ailment.Stmt.Assignment(8, ailment.Expr.Register(9, 16, 32), use_mse, ins_addr=0x1001),
        ],
        idx=0,
    )

    propagator = SPropagator(project, subject=block, ail_manager=manager)
    assert not _has_replacement(propagator, (tmp_use,))


@pytest.mark.parametrize("use_count", (1, 3))
@pytest.mark.parametrize(
    "mfx, expected_replacement",
    (("Ifx_Read", True), ("Ifx_Modify", False), (None, False)),
)
def test_spropagator_function_load_crosses_reads_but_not_dirty_writes(mfx, expected_replacement, use_count):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    vvar_def = VirtualVariable(1, 1, 32, VirtualVariableCategory.REGISTER, oident=16)
    vvar_uses = [
        VirtualVariable(idx + 2, 1, 32, VirtualVariableCategory.REGISTER, oident=16) for idx in range(use_count)
    ]
    statements: list[Statement] = [
        ailment.Stmt.Assignment(
            10,
            vvar_def,
            ailment.Expr.Load(11, addr, 4, "Iend_LE"),
            ins_addr=0x1000,
        ),
        _intervening_dirty_statement(12, mfx, addr),
    ]
    statements.extend(
        ailment.Stmt.Assignment(20 + idx, ailment.Expr.Register(30 + idx, 24 + idx * 4, 32), use, ins_addr=0x1002 + idx)
        for idx, use in enumerate(vvar_uses)
    )
    block = ailment.Block(0x1000, 1, statements=statements, idx=0)

    propagator = _function_propagator(project, block, manager)
    assert _has_replacement(propagator, vvar_uses) is expected_replacement


@pytest.mark.parametrize("use_count", (1, 3))
def test_spropagator_does_not_move_function_load_past_dirty_write_in_use_mse(use_count):
    project = _project()
    manager = ailment.Manager(arch=project.arch)
    addr = ailment.Expr.Const(0, 0x3000, 64)
    vvar_def = VirtualVariable(1, 1, 32, VirtualVariableCategory.REGISTER, oident=16)
    vvar_uses = [
        VirtualVariable(idx + 2, 1, 32, VirtualVariableCategory.REGISTER, oident=16) for idx in range(use_count)
    ]
    statements: list[Statement] = [
        ailment.Stmt.Assignment(
            10,
            vvar_def,
            ailment.Expr.Load(11, addr, 4, "Iend_LE"),
            ins_addr=0x1000,
        )
    ]
    statements.extend(
        ailment.Stmt.Assignment(
            20 + idx,
            ailment.Expr.Register(30 + idx, 24 + idx * 4, 32),
            _mse_use_with_dirty_write(40 + idx * 3, use, addr) if idx == 0 else use,
            ins_addr=0x1001 + idx,
        )
        for idx, use in enumerate(vvar_uses)
    )
    block = ailment.Block(0x1000, 1, statements=statements, idx=0)

    propagator = _function_propagator(project, block, manager)
    assert not _has_replacement(propagator, vvar_uses)
