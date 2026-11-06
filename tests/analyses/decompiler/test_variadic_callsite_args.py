#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
"""Tests for resolving variadic call-site arguments whose register has mixed-size reaching definitions.

In variadic_mixed_size_args (gcc -O2), report_mode() calls printf("mode=%lu\\n", v) where v lives in rsi and receives
definitions of different sizes on the three paths into the call block: two full-width defs (mov esi/mov rsi) and a
1-byte def (setne sil). SSA phi placement used to pass up creating a phi for rsi at the merge (mixed-size reaching
defs were assumed dead), while the variadic argument itself is only discovered by CallSiteMaker after SSA
construction, from the format string. The argument resolution then found multiple reaching virtual variables with no
phi merging them and crashed with `assert len(vvars) <= 1` in SRDAView.get_reg_vvar_by_stmt.

This is fixed by two changes:
- SRDAView returns None (no unique reaching definition) instead of asserting, and
- the SSA level-0 traversal records conservative argument-register uses at call sites with an uncertain argument
  count, so the phi exists and the variadic argument resolves to a unique, correctly merged virtual variable. With
  this fix, the ambiguous-register fallback in SRDAView must not trigger at all.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import re
import unittest
from typing import cast

import angr
from angr.analyses import Decompiler
from angr.analyses.decompiler.decompilation_options import get_structurer_option
from angr.analyses.decompiler.structured_codegen.base import PositionMapping
from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class _RecordingHandler(logging.Handler):
    """Collect log records emitted by a logger."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class TestVariadicCallsiteArgs(unittest.TestCase):
    def test_format_returned_by_gettext(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "dirname")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        func = cfg.functions[0x402946]

        for structurer in ("Phoenix", "SAILR"):
            with self.subTest(structurer=structurer):
                dec = proj.analyses[Decompiler].prep(fail_fast=True)(
                    func,
                    cfg=cfg.model,
                    options=[(get_structurer_option(), structurer)],
                    preset="full",
                )
                codegen = dec.codegen
                if codegen is None or codegen.text is None:
                    self.fail("decompilation did not produce C code")
                position_map = cast(PositionMapping | None, codegen.map_pos_to_node)
                if position_map is None:
                    self.fail("decompilation did not produce a C position map")
                print_decompilation_result(dec)

                formatted_output_calls = [
                    element.obj
                    for element in position_map.values()
                    if isinstance(element.obj, CFunctionCall)
                    and element.obj.callee_func is not None
                    and element.obj.callee_func.name in {"fprintf", "printf"}
                ]
                self.assertEqual(
                    len(formatted_output_calls), 3, f"expected three formatted output calls:\n{codegen.text}"
                )
                self.assertCountEqual(
                    [len(call.args) for call in formatted_output_calls],
                    [3, 2, 4],
                    "format strings returned by gettext() did not recover their variadic arguments",
                )

    def test_format_returned_by_dcgettext(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "ls_ubuntu2204")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        func = cfg.functions[0x417E80]

        for structurer in ("Phoenix", "SAILR"):
            with self.subTest(structurer=structurer):
                dec = proj.analyses[Decompiler].prep(fail_fast=True)(
                    func,
                    cfg=cfg.model,
                    options=[(get_structurer_option(), structurer)],
                    preset="full",
                )
                codegen = dec.codegen
                if codegen is None or codegen.text is None:
                    self.fail("decompilation did not produce C code")
                position_map = cast(PositionMapping | None, codegen.map_pos_to_node)
                if position_map is None:
                    self.fail("decompilation did not produce a C position map")
                print_decompilation_result(dec)

                printf_calls = [
                    element.obj
                    for element in position_map.values()
                    if isinstance(element.obj, CFunctionCall)
                    and element.obj.callee_func is not None
                    and element.obj.callee_func.name == "__printf_chk"
                ]
                self.assertEqual(len(printf_calls), 3, f"expected three __printf_chk() calls:\n{codegen.text}")
                self.assertCountEqual(
                    [len(call.args) for call in printf_calls],
                    [3, 4, 3],
                    "format strings returned by dcgettext() did not recover their variadic arguments",
                )

    def test_mixed_size_defs_of_variadic_arg_reg_are_phi_merged(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "variadic_mixed_size_args")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(recover_variables=False, analyze_callsites=True)

        func = cfg.functions["report_mode"]
        assert func is not None

        # capture the "no unique reaching definition" fallback of SRDAView; with conservative argument-register uses
        # in place, the variadic argument register must have a phi and the fallback must never fire
        srda_view_logger = logging.getLogger("angr.analyses.s_reaching_definitions.s_rda_view")
        handler = _RecordingHandler()
        old_level = srda_view_logger.level
        srda_view_logger.addHandler(handler)
        srda_view_logger.setLevel(logging.DEBUG)
        try:
            dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        finally:
            srda_view_logger.removeHandler(handler)
            srda_view_logger.setLevel(old_level)

        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text

        # the variadic argument must be discovered: printf takes the format string plus exactly one value argument
        m = re.search(r"printf\(\s*\"mode=%lu\\n\"\s*,\s*([^,()]+)\)", text)
        assert m is not None, (
            f"printf() call with the format string and exactly one variadic argument not found:\n{text}"
        )

        # the argument must not degrade to a raw register expression
        assert m.group(1).strip() not in ("rsi", "esi"), (
            f"the variadic argument degraded to a raw register expression: {m.group(1).strip()!r}"
        )

        # the ambiguous-register fallback must not have fired: every argument register with multiple reaching
        # definitions must have been merged by a phi node created during SSA construction
        fallback_records = [r for r in handler.records if "Multiple virtual variables" in r.getMessage()]
        assert not fallback_records, (
            "SRDAView found multiple reaching virtual variables with no phi node for a register: "
            + "; ".join(r.getMessage() for r in fallback_records)
        )


if __name__ == "__main__":
    unittest.main()
