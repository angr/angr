from __future__ import annotations

import angr
from angr.ailment import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment

from angr.rust.optimization_passes.utils import (
    extract_callee,
    extract_str,
    extract_str_from_addr,
    replace_argument_pairs,
)
from angr.rust.utils.ail import (
    deref_vvar_and_offset,
    extract_vvar_and_offset,
    find_call,
    get_terminal_call,
    has_call,
    unwrap_combo_reg_vvar_reference,
    unwrap_stack_vvar_reference,
    unwrap_stack_vvar_reference_with_offset,
)


def _stack_vvar(vvar_id: int = 0, offset: int = 16) -> VirtualVariable:
    return VirtualVariable(vvar_id, vvar_id, 64, VirtualVariableCategory.STACK, oident=offset)


def _reg_vvar(vvar_id: int = 0, offset: int = 16) -> VirtualVariable:
    return VirtualVariable(vvar_id, vvar_id, 64, VirtualVariableCategory.REGISTER, oident=offset)


def _combo_vvar(vvar_id: int = 0) -> VirtualVariable:
    return VirtualVariable(vvar_id, vvar_id, 128, VirtualVariableCategory.COMBO_REGISTER, oident=(16, 24))


def _ref(operand) -> UnaryOp:
    return UnaryOp(0, "Reference", operand)


def _const(value: int, bits: int = 64) -> Const:
    return Const(0, None, value, bits)


def test_unwrap_stack_vvar_reference_returns_underlying_vvar():
    vvar = _stack_vvar(offset=8)
    expr = _ref(vvar)
    assert unwrap_stack_vvar_reference(expr) is vvar


def test_unwrap_stack_vvar_reference_rejects_register_vvar():
    expr = _ref(_reg_vvar(offset=8))
    assert unwrap_stack_vvar_reference(expr) is None


def test_unwrap_stack_vvar_reference_rejects_non_reference_unary_op():
    expr = UnaryOp(0, "Neg", _stack_vvar())
    assert unwrap_stack_vvar_reference(expr) is None


def test_unwrap_combo_reg_vvar_reference_returns_underlying_vvar_only_for_combo():
    combo = _combo_vvar()
    assert unwrap_combo_reg_vvar_reference(_ref(combo)) is combo
    assert unwrap_combo_reg_vvar_reference(_ref(_reg_vvar())) is None


def test_deref_vvar_and_offset_handles_zero_and_offset_cases():
    vvar = _stack_vvar(offset=8)

    # Pure reference: offset 0
    assert deref_vvar_and_offset(_ref(vvar)) == (vvar, 0)

    # &vvar + 12 → (vvar, 12)
    add = BinaryOp(0, "Add", [_ref(vvar), _const(12)])
    assert deref_vvar_and_offset(add) == (vvar, 12)


def test_deref_vvar_and_offset_rejects_other_shapes():
    # Add of two vvars (no Reference): not the pattern.
    bogus = BinaryOp(0, "Add", [_stack_vvar(0), _stack_vvar(1)])
    assert deref_vvar_and_offset(bogus) == (None, None)
    # Sub of &vvar and const: also not the pattern.
    sub = BinaryOp(0, "Sub", [_ref(_stack_vvar()), _const(4)])
    assert deref_vvar_and_offset(sub) == (None, None)


def test_extract_vvar_and_offset_strips_constant_offset():
    vvar = _reg_vvar(offset=24)
    assert extract_vvar_and_offset(vvar) == (vvar, 0)
    assert extract_vvar_and_offset(BinaryOp(0, "Add", [vvar, _const(7)])) == (vvar, 7)
    assert extract_vvar_and_offset(_const(0)) == (None, None)


def test_unwrap_stack_vvar_reference_with_offset_returns_zero_for_plain_reference():
    vvar = _stack_vvar(offset=4)
    assert unwrap_stack_vvar_reference_with_offset(_ref(vvar)) == (vvar, 0)


def test_unwrap_stack_vvar_reference_with_offset_rejects_combo_register():
    assert unwrap_stack_vvar_reference_with_offset(_ref(_combo_vvar())) == (None, None)


def test_find_call_finds_call_inside_block_statement_assignment():
    target_call = Call(0, "callee_a", args=[])
    block = Block(
        0x4000,
        0,
        statements=[Assignment(0, _stack_vvar(0), target_call)],
    )

    found = find_call(block)
    assert found is target_call
    assert has_call(block) is True


def test_find_call_returns_none_when_no_call():
    block = Block(0x4010, 0, statements=[Assignment(0, _stack_vvar(0), _const(1))])
    assert find_call(block) is None
    assert has_call(block) is False


def test_get_terminal_call_returns_call_at_block_end():
    final_call = Call(1, "terminal_callee", args=[])
    block = Block(0x4020, 0, statements=[final_call])
    assert get_terminal_call(block) is final_call


def test_get_terminal_call_descends_into_assignment_with_call_rhs():
    inner_call = Call(2, "inner_callee", args=[])
    block = Block(
        0x4030,
        0,
        statements=[Assignment(0, _stack_vvar(0), inner_call)],
    )
    assert get_terminal_call(block) is inner_call


def test_get_terminal_call_returns_none_for_empty_block():
    block = Block(0x4040, 0, statements=[])
    assert get_terminal_call(block) is None


def test_replace_argument_pairs_no_args_short_circuits():
    call = Call(0, "callee", args=[])
    assert replace_argument_pairs(call, lambda a, b: (False, ())) is call


def test_replace_argument_pairs_collapses_consecutive_int_pairs():
    args = [_const(1), _const(2), _const(3), _const(4), _const(5)]
    call = Call(0, "callee", args=args)

    def merge_pair(a, b):
        if isinstance(a, Const) and isinstance(b, Const):
            return True, [_const(a.value + b.value)]
        return False, ()

    new_call = replace_argument_pairs(call, merge_pair)
    assert new_call is not call
    new_args = list(new_call.args)
    # Pairs are consumed left-to-right without reusing replacements:
    # (1,2)→3, (3,4)→7, leaving 5 unpaired ⇒ [3, 7, 5].
    assert [a.value for a in new_args] == [3, 7, 5]


def test_replace_argument_pairs_returns_original_when_no_replacement_happens():
    args = [_const(1), _const(2), _const(3)]
    call = Call(0, "callee", args=args)

    def never_replace(a, b):
        del a, b
        return False, ()

    assert replace_argument_pairs(call, never_replace) is call


def _project_with_synthetic_function(addr: int, name: str):
    project = angr.load_shellcode(b"\xc3" * 16, arch="amd64")
    project.kb.functions.function(addr=addr, name=name, create=True)
    return project


def test_extract_callee_returns_function_for_call_with_const_target():
    project = _project_with_synthetic_function(0x0, "callee")
    call = Call(0, Const(0, None, 0x0, 64), args=[])
    result = extract_callee(call, project.kb)
    assert result is project.kb.functions[0x0]


def test_extract_callee_walks_block_to_terminal_call():
    project = _project_with_synthetic_function(0x0, "callee")
    call = Call(0, Const(0, None, 0x0, 64), args=[])
    block = Block(0x100, 0, statements=[call])
    assert extract_callee(block, project.kb) is project.kb.functions[0x0]


def test_extract_callee_returns_none_for_unknown_target():
    project = _project_with_synthetic_function(0x0, "callee")
    unknown = Call(0, Const(0, None, 0xDEADBEEF, 64), args=[])
    assert extract_callee(unknown, project.kb) is None


def test_extract_callee_returns_none_for_non_block_non_call():
    project = _project_with_synthetic_function(0x0, "callee")
    assert extract_callee(Const(0, None, 0, 64), project.kb) is None


def test_extract_str_short_circuits_for_zero_length():
    project = angr.load_shellcode(b"\x90", arch="amd64")
    assert extract_str(project, str_ptr=0xDEAD, str_len=0) == ""


def test_extract_str_rejects_negative_pointer():
    project = angr.load_shellcode(b"\x90", arch="amd64")
    assert extract_str(project, str_ptr=-1, str_len=4) is None


def test_extract_str_returns_none_when_no_readable_section_covers_pointer():
    # load_shellcode produces a Blob with no sections, so find_section_containing
    # always returns None and the helper falls through to None.
    project = angr.load_shellcode(b"\x90", arch="amd64")
    assert extract_str(project, str_ptr=0x0, str_len=4) is None


def test_extract_str_from_addr_rejects_negative_address():
    project = angr.load_shellcode(b"\x90", arch="amd64")
    assert extract_str_from_addr(project, addr=-1) is None


def test_extract_str_from_addr_returns_none_when_no_section_covers_address():
    project = angr.load_shellcode(b"\x90", arch="amd64")
    assert extract_str_from_addr(project, addr=0x0) is None
