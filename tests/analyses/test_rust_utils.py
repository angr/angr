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
from angr.rust.utils.demangler import _is_rust_hash, demangle, normalize


def _stack_vvar(vvar_id: int = 0, offset: int = 16) -> VirtualVariable:
    return VirtualVariable(vvar_id, vvar_id, 64, VirtualVariableCategory.STACK, oident=offset)


def _reg_vvar(vvar_id: int = 0, offset: int = 16) -> VirtualVariable:
    return VirtualVariable(vvar_id, vvar_id, 64, VirtualVariableCategory.REGISTER, oident=offset)


def _combo_vvar(vvar_id: int = 0) -> VirtualVariable:
    return VirtualVariable(vvar_id, vvar_id, 128, VirtualVariableCategory.COMBO_REGISTER, oident=(16, 24))


def _ref(operand) -> UnaryOp:
    return UnaryOp(0, "Reference", operand)


def _const(value: int, bits: int = 64) -> Const:
    return Const(0, value, bits)


def test_unwrap_stack_vvar_reference_returns_underlying_vvar():
    vvar = _stack_vvar(offset=8)
    expr = _ref(vvar)
    assert unwrap_stack_vvar_reference(expr) == vvar


def test_unwrap_stack_vvar_reference_rejects_register_vvar():
    expr = _ref(_reg_vvar(offset=8))
    assert unwrap_stack_vvar_reference(expr) is None


def test_unwrap_stack_vvar_reference_rejects_non_reference_unary_op():
    expr = UnaryOp(0, "Neg", _stack_vvar())
    assert unwrap_stack_vvar_reference(expr) is None


def test_unwrap_combo_reg_vvar_reference_returns_underlying_vvar_only_for_combo():
    combo = _combo_vvar()
    assert unwrap_combo_reg_vvar_reference(_ref(combo)) == combo
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
    assert found == target_call
    assert has_call(block) is True


def test_find_call_returns_none_when_no_call():
    block = Block(0x4010, 0, statements=[Assignment(0, _stack_vvar(0), _const(1))])
    assert find_call(block) is None
    assert has_call(block) is False


def test_get_terminal_call_returns_call_at_block_end():
    final_call = Call(1, "terminal_callee", args=[])
    # get_terminal_call defensively handles raw Call expressions sitting at the end of a block.
    block = Block(0x4020, 0, statements=[final_call])  # pyright: ignore[reportArgumentType]
    assert get_terminal_call(block) is final_call


def test_get_terminal_call_descends_into_assignment_with_call_rhs():
    inner_call = Call(2, "inner_callee", args=[])
    block = Block(
        0x4030,
        0,
        statements=[Assignment(0, _stack_vvar(0), inner_call)],
    )
    assert get_terminal_call(block) == inner_call


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
            return True, [_const(int(a.value) + int(b.value))]
        return False, ()

    new_call = replace_argument_pairs(call, merge_pair)
    assert new_call is not call
    assert new_call.args is not None
    new_args = list(new_call.args)
    # Pairs are consumed left-to-right without reusing replacements:
    # (1,2)→3, (3,4)→7, leaving 5 unpaired ⇒ [3, 7, 5].
    values = []
    for a in new_args:
        assert isinstance(a, Const)
        values.append(a.value)
    assert values == [3, 7, 5]


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
    call = Call(0, Const(0, 0x0, 64), args=[])
    result = extract_callee(call, project.kb)
    assert result is project.kb.functions[0x0]


def test_extract_callee_walks_block_to_terminal_call():
    project = _project_with_synthetic_function(0x0, "callee")
    call = Call(0, Const(0, 0x0, 64), args=[])
    block = Block(0x100, 0, statements=[call])  # pyright: ignore[reportArgumentType]
    assert extract_callee(block, project.kb) is project.kb.functions[0x0]


def test_extract_callee_returns_none_for_unknown_target():
    project = _project_with_synthetic_function(0x0, "callee")
    unknown = Call(0, Const(0, 0xDEADBEEF, 64), args=[])
    assert extract_callee(unknown, project.kb) is None


def test_extract_callee_returns_none_for_non_block_non_call():
    project = _project_with_synthetic_function(0x0, "callee")
    assert extract_callee(Const(0, 0, 64), project.kb) is None


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


def test_is_rust_hash_accepts_only_17_char_hex_with_h_prefix():
    assert _is_rust_hash("h0123456789abcdef") is True
    assert _is_rust_hash("h12") is False  # too short
    assert _is_rust_hash("x0123456789abcdef") is False  # wrong prefix
    assert _is_rust_hash("h0123456789abcdez") is False  # non-hex digit


def test_demangle_strips_trailing_rust_hash_segment():
    mangled = "_ZN4core3fmt9Formatter9write_str17h0123456789abcdefE"
    assert demangle(mangled) == "core::fmt::Formatter::write_str"


def test_demangle_falls_back_to_original_string_when_unrecognized():
    raw = "not_a_rust_symbol"
    assert demangle(raw) == raw


def test_demangle_survives_malformed_rust_v0_symbol():
    # Regression for angr#6598: a garbage name that merely *looks* like a Rust v0 symbol
    # ("_R" prefix) makes the third-party rust_demangler walk past the end of its input and
    # leak a raw IndexError. demangle() must swallow it and fall back to the original string.
    raw = "_RBOJyX"
    assert demangle(raw) == raw


def test_demangle_survives_assorted_malformed_v0_symbols():
    # Various truncated/garbage "_R..." names that previously crashed the demangler with an
    # IndexError. Every one must fall through to a non-empty string without raising.
    for raw in ("_R", "_RNvC", "_RNvNtCs", "_RINvNtCs", "_RNvMC0", "_RNCNvC0"):
        result = demangle(raw)
        assert isinstance(result, str)
        assert result


def test_normalize_strips_generic_type_arguments_when_monopolizing():
    assert normalize("alloc::vec::Vec<u8>::push") == "alloc::vec::Vec::push"


def test_normalize_keeps_concrete_type_or_trait_name_per_flag():
    name = "<core::option::Option<T> as core::fmt::Debug>::fmt"
    assert normalize(name) == "core::option::Option::fmt"
    assert normalize(name, use_trait_name=True) == "core::fmt::Debug::fmt"


def test_normalize_handles_impl_as_pattern_using_trait_name():
    name = "<impl alloc::vec::Vec<u8> as core::iter::Iterator>::next"
    assert normalize(name) == "core::iter::Iterator::next"


def test_normalize_concise_returns_only_last_path_segment():
    assert normalize("foo::bar::baz", concise=True) == "baz"


def test_is_rust_hash_rejects_empty_and_short_inputs():
    assert _is_rust_hash("") is False
    assert _is_rust_hash("h") is False


def test_is_rust_hash_rejects_uppercase_hex_digits():
    # Cargo's hash suffix is always lowercase hex; uppercase must not match.
    assert _is_rust_hash("hABCDEF0123456789") is False


def test_demangle_handles_empty_string_without_raising():
    assert demangle("") == ""


def test_demangle_returns_input_for_legacy_symbol_with_no_hash_suffix():
    # A well-formed legacy symbol whose final segment isn't a 17-char h-hex hash:
    # the demangler still parses it, but our hash-stripping branch must not fire.
    mangled = "_ZN4core3fmt9Formatter9write_strE"
    out = demangle(mangled)
    # Whatever rust_demangler returns, our wrapper must not silently truncate the tail.
    assert out.endswith("write_str")


def test_demangle_passes_through_non_rust_input():
    # Inputs that aren't recognized as Rust mangled names fall through unchanged.
    for raw in ("plain_c_symbol", "main", "?something@msvc@@", "_Z3fooi"):
        # _Z3fooi is itanium C++ mangling; rust_demangler may or may not raise,
        # but the wrapper must always return a non-None string for non-Rust input.
        result = demangle(raw)
        assert isinstance(result, str)
        assert result  # non-empty


def test_normalize_strips_nested_generic_brackets():
    # Multi-level generics must collapse fully under monopolize.
    assert normalize("alloc::vec::Vec<Box<u8>>::push") == "alloc::vec::Vec::push"


def test_normalize_monopolize_false_preserves_generic_arguments():
    name = "alloc::vec::Vec<u8>::push"
    assert normalize(name, monopolize=False) == name


def test_normalize_concise_with_trait_uses_last_segment_after_trait_substitution():
    name = "<core::option::Option<T> as core::fmt::Debug>::fmt"
    assert normalize(name, use_trait_name=True, concise=True) == "fmt"


def test_normalize_idempotent_under_repeated_calls():
    name = "<impl alloc::vec::Vec<u8> as core::iter::Iterator>::next"
    once = normalize(name)
    twice = normalize(once)
    assert once == twice
