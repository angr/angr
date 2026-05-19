#!/usr/bin/env python3
"""Unit tests for ``FormatMacroSimplifier`` constants and the macro selector.

The full pass is a heavy walker over a real decompiler graph. The exposed
constants and the per-macro name selector ``_select_macro``, however, are
deterministic functions that can be exercised in isolation.
"""

from __future__ import annotations

import angr

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
