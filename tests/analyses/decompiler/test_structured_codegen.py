#!/usr/bin/env python3
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
import unittest

import archinfo

from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeGenerator
from angr.sim_type import SimTypeInt
from angr.sim_variable import SimStackVariable


class TestStructuredCodegen(unittest.TestCase):
    """Regression tests for structured-codegen helpers."""

    def test_iter_stack_frame_fields_includes_terminal_stack_slot(self):
        codegen = object.__new__(CStructuredCodeGenerator)
        codegen_any = cast(Any, codegen)
        codegen_any.project = SimpleNamespace(arch=archinfo.ArchAMD64())

        last_var = SimStackVariable(-0x10, 4, ident="stack_0")
        codegen_any._stack_var_field_names_by_offset = {last_var.offset: "v0"}
        codegen_any._stack_var_ref_names = {last_var: "stack_frame.v0"}
        codegen_any.stackvar_max_sizes = {}
        codegen_any._get_variable_type = lambda var, is_global=False: SimTypeInt().with_arch(codegen.project.arch)

        fields = list(codegen.iter_stack_frame_fields())

        self.assertEqual(len(fields), 1)
        field_name, field_type = fields[0]
        self.assertEqual(field_name, "v0")
        self.assertEqual(field_type.c_repr(field_name), "int v0")


if __name__ == "__main__":
    unittest.main()
