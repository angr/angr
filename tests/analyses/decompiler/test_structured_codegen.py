#!/usr/bin/env python3
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
import unittest

import archinfo

from angr.analyses.decompiler.structured_codegen.c import (
    CFakeVariable,
    CStructField,
    CTypeCast,
    CVariableField,
    CStructuredCodeGenerator,
    CVariable,
    PromotedStackArrayFixer,
    _normalize_value_type,
    _stack_array_is_scalar_promotion,
    _stack_array_spans_multiple_slots,
)
from angr.sim_type import SimStruct, SimTypeArray, SimTypeChar, SimTypeInt, SimTypePointer
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

    def test_normalize_value_type_scalarizes_array_casts(self):
        codegen = object.__new__(CStructuredCodeGenerator)
        codegen_any = cast(Any, codegen)
        codegen_any.project = SimpleNamespace(
            arch=archinfo.ArchX86(), loader=SimpleNamespace(main_object=SimpleNamespace(binary="unit-test"))
        )

        array_type = SimTypeArray(SimTypeChar().with_arch(codegen.project.arch), 4).with_arch(codegen.project.arch)
        normalized = _normalize_value_type(array_type, codegen, SimTypeChar().with_arch(codegen.project.arch))

        self.assertIsInstance(normalized, SimTypeInt)
        self.assertEqual(normalized.c_repr(), "int")

    def test_single_slot_stack_array_can_scalarize(self):
        codegen = object.__new__(CStructuredCodeGenerator)
        codegen_any = cast(Any, codegen)
        codegen_any.project = SimpleNamespace(
            arch=archinfo.ArchX86(), loader=SimpleNamespace(main_object=SimpleNamespace(binary="unit-test"))
        )
        codegen_any._variables_in_use = {}
        codegen_any._promoted_stack_arrays = set()
        codegen_any._promoted_stack_scalars = set()
        codegen_any._promoted_stack_scalar_types = {}
        codegen_any.idx_counters = {}
        codegen_any.stack_var_ref_name = lambda var: None
        codegen_any.display_vvar_ids = False

        stack_var = SimStackVariable(-0x10, 1, ident="stack_0")
        array_type = SimTypeArray(SimTypeChar(signed=False).with_arch(codegen.project.arch), 4).with_arch(
            codegen.project.arch
        )
        cvar = CVariable(stack_var, variable_type=array_type, codegen=codegen)
        codegen_any._variables_in_use[stack_var] = cvar

        self.assertTrue(_stack_array_spans_multiple_slots(stack_var, array_type, codegen.project.arch))
        self.assertTrue(_stack_array_is_scalar_promotion(stack_var, array_type, codegen.project.arch))

        fixer = PromotedStackArrayFixer()
        scalar = fixer._scalarized_stack_array(cvar, SimTypeInt(signed=True).with_arch(codegen.project.arch))

        self.assertIsInstance(scalar.type, SimTypeChar)
        self.assertTrue(scalar.type.signed)
        self.assertIn(stack_var, codegen._promoted_stack_scalars)
        self.assertTrue(codegen._promoted_stack_scalar_types[stack_var].signed)

    def test_stack_array_pointer_context_does_not_scalarize(self):
        codegen = object.__new__(CStructuredCodeGenerator)
        codegen_any = cast(Any, codegen)
        codegen_any.project = SimpleNamespace(
            arch=archinfo.ArchX86(), loader=SimpleNamespace(main_object=SimpleNamespace(binary="unit-test"))
        )
        codegen_any._variables_in_use = {}
        codegen_any._promoted_stack_arrays = set()
        codegen_any._promoted_stack_scalars = set()
        codegen_any._promoted_stack_scalar_types = {}
        codegen_any.idx_counters = {}
        codegen_any.stack_var_ref_name = lambda var: None
        codegen_any.display_vvar_ids = False

        stack_var = SimStackVariable(-0x10, 1, ident="stack_0")
        array_type = SimTypeArray(SimTypeChar(signed=False).with_arch(codegen.project.arch), 4).with_arch(
            codegen.project.arch
        )
        cvar = CVariable(stack_var, variable_type=array_type, codegen=codegen)
        codegen_any._variables_in_use[stack_var] = cvar

        fixer = PromotedStackArrayFixer()
        pointer_expr = fixer._scalarized_stack_array(
            cvar, SimTypePointer(SimTypeChar().with_arch(codegen.project.arch)).with_arch(codegen.project.arch)
        )

        self.assertIs(pointer_expr, cvar)
        self.assertNotIn(stack_var, codegen._promoted_stack_scalars)

    def test_c_type_cast_scalarizes_array_field_reads(self):
        codegen = object.__new__(CStructuredCodeGenerator)
        codegen_any = cast(Any, codegen)
        codegen_any.project = SimpleNamespace(
            arch=archinfo.ArchAMD64(), loader=SimpleNamespace(main_object=SimpleNamespace(binary="unit-test"))
        )
        codegen_any.show_casts = True
        codegen_any.display_vvar_ids = False
        codegen_any.stack_var_ref_name = lambda var: None
        codegen_any.idx_counters = {}
        codegen_any.stmt_comments = {}

        arch = codegen.project.arch
        struct_ty = SimStruct(
            {
                "field_0": SimTypeArray(SimTypeChar(signed=False).with_arch(arch), 4).with_arch(arch),
                "field_4": SimTypeInt(signed=False).with_arch(arch),
            },
            name="struct_0",
        ).with_arch(arch)
        cur = CFakeVariable("cur", SimTypePointer(struct_ty).with_arch(arch), codegen=codegen)
        field = CVariableField(
            cur, CStructField(struct_ty, 0, "field_0", codegen=codegen), var_is_ptr=True, codegen=codegen
        )

        expr = CTypeCast(field.type, SimTypeInt(signed=False).with_arch(arch), field, codegen=codegen)

        self.assertEqual("".join(chunk for chunk, _ in expr.c_repr_chunks()), "*((unsigned int *)cur->field_0)")


if __name__ == "__main__":
    unittest.main()
