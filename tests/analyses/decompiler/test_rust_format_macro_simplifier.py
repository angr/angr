#!/usr/bin/env python3
"""Unit tests for ``FormatMacroSimplifier`` constants and the macro selector.

The full pass is a heavy walker over a real decompiler graph. The exposed
constants and the per-macro name selector ``_select_macro``, however, are
deterministic functions that can be exercised in isolation.
"""

from __future__ import annotations

import angr
from angr.rust.optimization_passes.macro.fmt_template import Placeholder, decode_template, num_args
from angr.rust.optimization_passes.macro.format_macro_simplifier import (
    FORMAT_FUNCTIONS,
    NEW_ARGUMENT_FUNCTION,
    NEW_ARGUMENTS_FUNCTION,
    FormatMacroSimplifier,
)
from angr.rust.sim_type import RustSimTypeSize


def test_format_functions_list_covers_known_print_and_panic_targets():
    # Lock down the exact set of fully-qualified target names the simplifier
    # treats as format-call sinks. Drift in production code will surface here
    # before integration tests run.
    expected_subset = {
        "std::io::stdio::_print",
        "std::io::stdio::_eprint",
        "core::panicking::panic_fmt",
        "core::fmt::write",
        "alloc::fmt::format",
    }
    assert expected_subset.issubset(set(FORMAT_FUNCTIONS))


def test_format_functions_list_has_no_duplicates():
    assert len(FORMAT_FUNCTIONS) == len(set(FORMAT_FUNCTIONS))


def test_new_arguments_function_constants_are_distinct_and_well_formed():
    # Two distinct constructor entry-points: new_v1 and new_const.
    assert len(NEW_ARGUMENTS_FUNCTION) == 2
    for name in NEW_ARGUMENTS_FUNCTION:
        assert name.startswith("core::fmt::rt::")
        assert "Arguments" in name


def test_new_argument_function_constant_is_singleton():
    assert NEW_ARGUMENT_FUNCTION == ("core::fmt::rt::Argument::new_display",)


def _format_simplifier_with_kb(known_structs=None) -> FormatMacroSimplifier:
    """Build a FormatMacroSimplifier without invoking its full ``__init__``.

    ``_select_macro`` only reads ``self.project.kb.known_structs`` in the
    ``format`` arm; for that arm we plant a stub on the function via
    ``__class__.__setattr__``.
    """
    project = angr.load_shellcode(b"\x90", arch="amd64")
    func = project.kb.functions.function(addr=0x0, name="dummy", create=True)
    simp = object.__new__(FormatMacroSimplifier)
    simp._func = func  # pyright: ignore[reportAttributeAccessIssue]
    if known_structs is not None:
        # known_structs is a knowledge plugin; the simplifier reads it as a
        # mapping. Patch the plugin's storage directly so reads pass through.
        for name, ty in known_structs.items():
            project.kb.known_structs[name] = ty  # pyright: ignore[reportArgumentType]
    return simp


def test_select_macro_chooses_println_for_print_with_trailing_newline():
    simp = _format_simplifier_with_kb()
    macro, body, returnty = simp._select_macro("std::io::stdio::_print", "Hello\n")
    assert macro == "println"
    assert body == "Hello"
    assert returnty is None


def test_select_macro_chooses_print_when_no_trailing_newline():
    simp = _format_simplifier_with_kb()
    macro, body, _ = simp._select_macro("std::io::stdio::_print", "Hello")
    assert macro == "print"
    assert body == "Hello"


def test_select_macro_chooses_eprintln_and_eprint_for_stderr_variants():
    simp = _format_simplifier_with_kb()
    macro_ln, _, _ = simp._select_macro("std::io::stdio::_eprint", "boom\n")
    macro, _, _ = simp._select_macro("std::io::stdio::_eprint", "boom")
    assert macro_ln == "eprintln"
    assert macro == "eprint"


def test_select_macro_chooses_panic_for_panic_fmt():
    simp = _format_simplifier_with_kb()
    macro, body, returnty = simp._select_macro("core::panicking::panic_fmt", "boom")
    assert macro == "panic"
    assert body == "boom"
    assert returnty is None


def test_select_macro_chooses_writeln_returnty_is_usize():
    simp = _format_simplifier_with_kb()
    macro, body, returnty = simp._select_macro("std::io::Write::write_fmt", "line\n")
    assert macro == "writeln"
    assert body == "line"
    assert isinstance(returnty, RustSimTypeSize)


def test_select_macro_chooses_write_returnty_is_usize():
    simp = _format_simplifier_with_kb()
    macro, body, returnty = simp._select_macro("std::io::Write::write_fmt", "line")
    assert macro == "write"
    assert body == "line"
    assert isinstance(returnty, RustSimTypeSize)


def _decode(data: bytes):
    def read(addr, size):
        return data[addr : addr + size] if addr + size <= len(data) else None

    return decode_template(read, 0)


def test_decode_template_pieces_and_specs():
    # "0x{:08x} {1:>5} {:#?}"
    flags_zero_pad_width = (0x6900_0020).to_bytes(4, "little")
    flags_right_width = (0x2800_0020).to_bytes(4, "little")
    flags_alternate = (0x6080_0020).to_bytes(4, "little")
    data = (
        b"\x020x"
        + b"\xc3"
        + flags_zero_pad_width
        + (8).to_bytes(2, "little")
        + b"\x01 "
        + b"\xcb"
        + flags_right_width
        + (5).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + b"\x01 "
        + b"\xc1"
        + flags_alternate
        + b"\x00"
    )
    pieces = _decode(data)
    assert pieces is not None
    assert [p for p in pieces if isinstance(p, str)] == ["0x", " ", " "]
    placeholders = [p for p in pieces if isinstance(p, Placeholder)]
    assert [p.arg_index for p in placeholders] == [0, 1, 2]
    assert [p.spec(t) for p, t in zip(placeholders, ["x", "", "?"])] == ["08x", ">5", "#?"]
    assert num_args(pieces) == 3


def test_decode_template_rejects_garbage():
    assert _decode(b"\x05abc") is None  # truncated
    assert _decode(b"\x90\x00") is None  # 0x81..0xbf is not a valid opcode
    assert _decode(b"\x02\xff\xfe\x00") is None  # invalid utf-8


def test_placeholder_spec_with_dynamic_counts():
    # "{1:2$}" and "{:>.3$}"
    assert Placeholder(arg_index=1, flags=0x6800_0020, width=2, width_indirect=True).spec("") == "2$"
    assert Placeholder(arg_index=0, flags=0x3000_0020, precision=3, precision_indirect=True).spec("") == ">.3$"
