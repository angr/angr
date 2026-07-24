from __future__ import annotations

import angr
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Insert,
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.analyses.decompiler.optimization_passes.inlined_strcpy_simplifier import InlinedStrcpySimplifier
from angr.analyses.decompiler.optimization_passes.inlined_wcscpy_simplifier import InlinedWcscpySimplifier
from angr.analyses.decompiler.variable_map import variable_map_of


def _simplifier(cls):
    project = angr.load_shellcode(b"\x90", arch="AMD64")
    func = project.kb.functions.function(addr=0, name="dummy", create=True)
    simplifier = object.__new__(cls)
    simplifier._func = func  # pyright: ignore[reportAttributeAccessIssue]
    simplifier.manager = Manager()
    return simplifier


def _stack_vvar(varid: int, offset: int, bits: int = 32):
    return VirtualVariable(varid, varid, bits, VirtualVariableCategory.STACK, oident=offset)


def _register_vvar(varid: int, bits: int = 64):
    return VirtualVariable(varid, varid, bits, VirtualVariableCategory.REGISTER, oident=0)


def _float_const(idx: int, value: float = 1.0, bits: int = 32):
    return Const(idx, value, bits)  # pyright: ignore[reportArgumentType]


def _integer_stack_assignment(idx: int, offset: int):
    return Assignment(idx, _stack_vvar(idx, offset), Const(idx, 0x41414141, 32))


def _inlined_wcsncpy(simplifier, idx: int, offset: int, data: bytes, count=None):
    string_id = simplifier.kb.custom_strings.allocate(data)
    string_const = Const(idx, string_id, 64)
    variable_map_of(simplifier.manager).set_custom_string(string_const)
    if count is None:
        count = Const(idx + 1, len(data) // 2, 64)
    call = Call(
        idx + 2,
        "wcsncpy",
        args=[StackBaseOffset(idx + 3, 64, offset), string_const, count],
    )
    return SideEffectStatement(idx + 4, call)


def test_strcpy_collector_rejects_float_stack_assignment():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    statements = [
        _integer_stack_assignment(0, -8),
        Assignment(1, _stack_vvar(1, -4), _float_const(1)),
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert collected[-4][1] is None


def test_strcpy_collector_rejects_float_insert_value_and_offset():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = _stack_vvar(1, -4)
    statements = [
        _integer_stack_assignment(0, -8),
        Assignment(1, dst, Insert(1, dst, Const(2, 0, 32), _float_const(3), "Iend_LE")),
    ]
    collected = simplifier._collect_constant_stores(statements, 0)
    assert collected[-4][1] is None

    statements[1] = Assignment(
        1,
        dst,
        Insert(1, dst, _float_const(2, 0.0), Const(3, 0x41, 8), "Iend_LE"),
    )
    collected = simplifier._collect_constant_stores(statements, 0)
    assert collected[-4][1] is None


def test_strcpy_collector_rejects_float_insert_base():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = _stack_vvar(1, -8)
    statements = [
        Assignment(
            1,
            dst,
            Insert(1, _float_const(2), Const(3, 4, 32), Const(4, 0x44434241, 32), "Iend_LE"),
        )
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert -4 not in collected
    assert collected[-8][1] is None


def test_strcpy_single_statement_rejects_float_insert_offset():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = _stack_vvar(0, -4)
    stmt = Assignment(
        0,
        dst,
        Insert(0, dst, _float_const(1, 0.0), Const(2, 0x44434241, 32), "Iend_LE"),
    )

    assert simplifier._optimize_single_stmt(stmt, 0, [stmt]) is None


def test_strcpy_single_statement_rejects_float_insert_base():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = _stack_vvar(0, -4)
    stmt = Assignment(
        0,
        dst,
        Insert(0, _float_const(1), Const(2, 0, 32), Const(3, 0x44434241, 32), "Iend_LE"),
    )

    assert simplifier._optimize_single_stmt(stmt, 0, [stmt]) is None


def test_strcpy_collector_rejects_float_stack_store():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    statements = [
        _integer_stack_assignment(0, -8),
        Store(1, StackBaseOffset(1, 64, -4), _float_const(1), 4, "Iend_LE"),
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert collected[-4][1] is None


def test_strcpy_collector_keeps_integer_insert_and_stack_store():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = _stack_vvar(0, -8)
    statements = [
        Assignment(0, dst, Insert(0, dst, Const(1, 0, 32), Const(2, 0x44434241, 32), "Iend_LE")),
        Store(1, StackBaseOffset(1, 64, -4), Const(3, 0x48474645, 32), 4, "Iend_LE"),
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert collected[-8][1].is_int
    assert collected[-4][1].is_int


def test_strcpy_consolidation_rejects_float_store():
    simplifier = _simplifier(InlinedStrcpySimplifier)
    dst = StackBaseOffset(0, 64, -8)
    string_id = simplifier.kb.custom_strings.allocate(b"abcd")
    string_const = Const(1, string_id, 64)
    variable_map_of(simplifier.manager).set_custom_string(string_const)
    call = Call(2, "strncpy", args=[dst, string_const, Const(3, 4, 64)])
    inlined_strcpy = SideEffectStatement(4, call)
    float_store = Store(5, StackBaseOffset(5, 64, -4), _float_const(6), 4, "Iend_LE")

    assert simplifier._consolidate_pair(inlined_strcpy, float_store) is None


def test_strcpy_address_parser_rejects_float_offset():
    base = _register_vvar(0)
    addr = BinaryOp(1, "Add", [base, _float_const(2, 4.0, 64)])

    assert InlinedStrcpySimplifier._get_delta(base, addr) is None


def test_wcscpy_collector_rejects_float_stack_assignment():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    statements = [
        _integer_stack_assignment(0, -8),
        Assignment(1, _stack_vvar(1, -4), _float_const(1)),
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert collected[-4][1] is None


def test_wcscpy_collector_rejects_float_store_and_offset():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    base = _register_vvar(0)
    statements = [
        Store(0, base, Const(0, 0x41004200, 32), 4, "Iend_LE"),
        Store(
            1,
            BinaryOp(1, "Add", [base, Const(1, 4, 64)]),
            _float_const(1),
            4,
            "Iend_LE",
        ),
    ]
    collected = simplifier._collect_constant_stores(statements, 0)
    assert collected[4][1] is None

    statements[1] = Store(
        1,
        BinaryOp(1, "Add", [base, _float_const(1, 4.0, 64)]),
        Const(1, 0x43004400, 32),
        4,
        "Iend_LE",
    )
    collected = simplifier._collect_constant_stores(statements, 0)
    assert 4 not in collected


def test_wcscpy_collector_keeps_integer_store_and_offset():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    base = _register_vvar(0)
    statements = [
        Store(0, base, Const(0, 0x41004200, 32), 4, "Iend_LE"),
        Store(
            1,
            BinaryOp(1, "Add", [base, Const(1, 4, 64)]),
            Const(2, 0x43004400, 32),
            4,
            "Iend_LE",
        ),
    ]

    collected = simplifier._collect_constant_stores(statements, 0)

    assert collected[0][1].is_int
    assert collected[4][1].is_int


def test_wcscpy_consolidation_preserves_float_store_as_overlap_barrier():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    call = _inlined_wcsncpy(simplifier, 0, 0, b"A\x00B\x00")
    float_store = Store(5, StackBaseOffset(6, 64, 4), _float_const(7, bits=16), 2, "Iend_LE")
    final_store = Store(8, StackBaseOffset(9, 64, 4), Const(10, 0, 16), 2, "Iend_LE")

    assert simplifier._consolidate_wcscpy_calls([call, final_store]) is not None
    assert simplifier._consolidate_wcscpy_calls([call, float_store, final_store]) is None


def test_wcscpy_consolidation_preserves_float_assignment_as_overlap_barrier():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    call = _inlined_wcsncpy(simplifier, 0, 0, b"A\x00B\x00")
    float_assignment = Assignment(5, _stack_vvar(6, 4, bits=16), _float_const(7, bits=16))
    final_assignment = Assignment(8, _stack_vvar(9, 4, bits=16), Const(10, 0x43, 16))

    assert simplifier._consolidate_wcscpy_calls([call, final_assignment]) is not None
    assert simplifier._consolidate_wcscpy_calls([call, float_assignment, final_assignment]) is None


def test_wcscpy_consolidation_aborts_on_noninteger_wcsncpy_count():
    simplifier = _simplifier(InlinedWcscpySimplifier)
    invalid_call = _inlined_wcsncpy(simplifier, 0, 8, b"C\x00", count=_float_const(1, 1.0, 64))
    valid_call = _inlined_wcsncpy(simplifier, 10, 0, b"A\x00B\x00")
    final_store = Store(20, StackBaseOffset(21, 64, 4), Const(22, 0, 16), 2, "Iend_LE")

    assert simplifier._consolidate_wcscpy_calls([valid_call, final_store]) is not None
    assert simplifier._consolidate_wcscpy_calls([invalid_call, valid_call, final_store]) is None


def test_wcscpy_wide_string_predicates_reject_floats():
    assert not InlinedWcscpySimplifier.even_offsets_are_zero([0.0, 65.0])
    assert not InlinedWcscpySimplifier.odd_offsets_are_zero([65.0, 0.0])
    assert InlinedWcscpySimplifier.is_integer_likely_a_wide_string(1.0, 4, "Iend_LE") == (False, None)
